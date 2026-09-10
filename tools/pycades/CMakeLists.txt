CMAKE_MINIMUM_REQUIRED(VERSION 3.5)
SET(Python_INCLUDE_DIR "@PY_INC@")
PROJECT(PythonModule LANGUAGES CXX)
    SET (pycades_LIB_SRCS
            errormsg.cpp
            PyCades.cpp
            PyCadesAbout.cpp
            PyCadesAlgorithm.cpp
            PyCadesAttribute.cpp
            PyCadesAttributes.cpp
            PyCadesBasicConstraints.cpp
            PyCadesBlobs.cpp
            PyCadesCertificate.cpp
            PyCadesCertificates.cpp
            PyCadesCertificateStatus.cpp
            PyCadesCRL.cpp
            PyCadesEncodedData.cpp
            PyCadesEnvelopedData.cpp
            PyCadesEKU.cpp
            PyCadesEKUs.cpp
            PyCadesExtendedKeyUsage.cpp
            PyCadesHashedData.cpp
            PyCadesKeyUsage.cpp
            PyCadesOID.cpp
            PyCadesPrivateKey.cpp
            PyCadesPublicKey.cpp
            PyCadesRawSignature.cpp
            PyCadesRecipients.cpp
            PyCadesSignatureStatus.cpp
            PyCadesSignedData.cpp
            PyCadesSignedXML.cpp
            PyCadesSigner.cpp
            PyCadesSigners.cpp
            PyCadesStore.cpp
            PyCadesSymmetricAlgorithm.cpp
            PyCadesVersion.cpp
        )
FIND_PACKAGE( Boost REQUIRED )

ADD_DEFINITIONS(-DUNIX -DSIZEOF_VOID_P=${CMAKE_SIZEOF_VOID_P})

#SET(CMAKE_BUILD_TYPE Debug)
SET(CMAKE_CXX_FLAGS  "${CMAKE_CXX_FLAGS} -Wno-write-strings")
SET(CMAKE_CXX_FLAGS  "${CMAKE_CXX_FLAGS} -Wno-deprecated-declarations")
SET(CMAKE_CXX_FLAGS  "${CMAKE_CXX_FLAGS} -Wno-narrowing")
SET(CMAKE_CXX_FLAGS  "${CMAKE_CXX_FLAGS} -include algorithm -include memory -include vector -include string -include map -include sstream -include iostream -include functional")
SET(CMAKE_INCLUDE_CURRENT_DIR ON)
SET(pycades_DIRS
     @STUB@
     @DEV@
     @DEV@/cpcsp
     /opt/cprocsp/include
     /opt/cprocsp/include/cpcsp
     /opt/cprocsp/include/pki/atl
     /opt/cprocsp/include/pki/cppcades
     /opt/cprocsp/include/pki/cplib
     /opt/cprocsp/include/pki
     @DEV@/pki/atl
     @DEV@/pki/cplib
     @DEV@/pki/cppcades
     @DEV@/pki
)    

INCLUDE_DIRECTORIES( ${Boost_INCLUDE_DIRS} )
INCLUDE_DIRECTORIES( ${Python_INCLUDE_DIR})
INCLUDE_DIRECTORIES( ${pycades_DIRS})

ADD_LIBRARY(pycades SHARED ${pycades_LIB_SRCS})
SET_TARGET_PROPERTIES(pycades PROPERTIES PREFIX "")

# CryptoPro::CBlob / CStringProxy live in different libraries across CSP
# releases (libcplib on 5.0.12000; libcades/libcppcades on 5.0.13800).  Link
# whichever of the candidates actually exist; undefined symbols are allowed
# and resolved at import time from the preloaded CSP libraries.
SET(CP_LIB_DIR /opt/cprocsp/lib/amd64)
SET(PYCADES_LIBS "")
FOREACH(cand cppcades cades xades cplib cpasn1 capi10 capi20 rdrsup)
    FIND_LIBRARY(FOUND_${cand} NAMES ${cand}
        HINTS ${CP_LIB_DIR} /opt/cprocsp/lib/ia32 /opt/cprocsp/lib/aarch64)
    IF(FOUND_${cand})
        LIST(APPEND PYCADES_LIBS ${FOUND_${cand}})
    ENDIF()
ENDFOREACH()
TARGET_LINK_LIBRARIES(pycades ${PYCADES_LIBS})

ADD_CUSTOM_COMMAND(TARGET pycades
    POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:pycades> ..)
