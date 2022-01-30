FROM openjdk:8
EXPOSE 8080
ADD target/encryption-decryption-lib.jar encryption-decryption-lib.jar
ENTRYPOINT ["java","-jar","/encryption-decryption-lib.jar"]
