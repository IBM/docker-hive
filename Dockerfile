FROM azul/zulu-openjdk-debian:11.0.11

WORKDIR /opt

ENV HADOOP_HOME=/opt/hadoop-3.3.1
ENV HIVE_HOME=/opt/apache-hive-3.1.2-bin
# Include additional jars
ENV HADOOP_CLASSPATH=/opt/hadoop-3.3.1/share/hadoop/tools/lib/aws-java-sdk-bundle-1.12.133.jar:/opt/hadoop-3.3.1/share/hadoop/tools/lib/hadoop-aws-3.3.1.jar

RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get -qqy install curl && \
    curl -L https://dlcdn.apache.org/hive/hive-3.1.2/apache-hive-3.1.2-bin.tar.gz | tar zxf - && \
    curl -L https://dlcdn.apache.org/hadoop/common/hadoop-3.3.1/hadoop-3.3.1.tar.gz | tar zxf - && \
    apt-get install --only-upgrade openssl libssl1.1 && \
    apt-get install -y libk5crypto3 libkrb5-3 libsqlite3-0 zip

RUN rm ${HIVE_HOME}/lib/postgresql-9.4.1208.jre7.jar

RUN curl -o ${HIVE_HOME}/lib/postgresql-9.4.1212.jre7.jar -L https://jdbc.postgresql.org/download/postgresql-9.4.1212.jre7.jar

COPY conf ${HIVE_HOME}/conf

RUN groupadd -r hive --gid=1000 && \
    useradd -r -g hive --uid=1000 -d ${HIVE_HOME} hive && \
    chown hive:hive -R ${HIVE_HOME}

RUN zip -q -d /opt/apache-hive-*-bin/lib/log4j-core-*.jar org/apache/logging/log4j/core/lookup/JndiLookup.class
ARG LOG4J_VERSION=2.17.1
ARG LOG4J_LOCATION="https://repo1.maven.org/maven2/org/apache/logging/log4j"
RUN \
    rm -f /opt/hadoop-*/share/hadoop/common/lib/log4j-* && \
    rm -f /opt/hadoop-*/share/hadoop/hdfs/lib/log4j-* && \
    rm -f /opt/apache-hive-*-bin/lib/log4j-* && \
    curl -o ${HIVE_HOME}/lib/log4j-1.2-api-${LOG4J_VERSION}.jar ${LOG4J_LOCATION}/log4j-1.2-api/${LOG4J_VERSION}/log4j-1.2-api-${LOG4J_VERSION}.jar  && \
    curl -o ${HIVE_HOME}/lib/log4j-api-${LOG4J_VERSION}.jar ${LOG4J_LOCATION}/log4j-api/${LOG4J_VERSION}/log4j-api-${LOG4J_VERSION}.jar && \
    curl -o ${HIVE_HOME}/lib/log4j-core-${LOG4J_VERSION}.jar ${LOG4J_LOCATION}/log4j-core/${LOG4J_VERSION}/log4j-core-${LOG4J_VERSION}.jar && \
    curl -o ${HIVE_HOME}/lib/log4j-slf4j-impl-${LOG4J_VERSION}.jar ${LOG4J_LOCATION}/log4j-slf4j-impl/${LOG4J_VERSION}/log4j-slf4j-impl-${LOG4J_VERSION}.jar

USER hive
WORKDIR $HIVE_HOME
EXPOSE 9083

ENTRYPOINT ["bin/hive"]
CMD ["--service", "metastore"]
