FROM azul/zulu-openjdk-debian:8-jre

# Settings for the container
ENV HIVE_LOGLEVEL="info" \
    HADOOP_VERSION=3.3.4 \
    HIVE_VERSION=3.1.3 \
    TEZ_VERSION=0.10.2 \
    LOG4J_VERSION=2.19.0 \
    HADOOP_CONNECTORS_VERSION=2.2.10 \
    CLOUD_SQL_VERSION=1.8.0 \
    HADOOP_HOME=/opt/hadoop \
    HIVE_HOME=/opt/hive \ 
    TEZ_HOME=/opt/tez

ENV LOG4J_LOCATION="https://repo1.maven.org/maven2/org/apache/logging/log4j" \
    HADOOP_CLASSPATH="${TEZ_HOME}/*:${TEZ_HOME}/lib/*" \
    PATH=${HIVE_HOME}/bin:${HADOOP_HOME}/bin:$PATH

RUN useradd -d ${HIVE_HOME} -m -u 1002 -U hive && \
    mkdir ${HADOOP_HOME} && \
    mkdir ${TEZ_HOME} && \
    chown -R hive:hive /opt && \
    apt-get update && \
    apt-get upgrade -y && \
    DEBIAN_FRONTEND=noninteractive apt-get -qqy install \
        curl \
        openssl \
        libssl1.1 \
        libexpat1 \
        libk5crypto3 \
        libkrb5-3 \
        libsqlite3-0 \
        # Needed by hive scripts
        procps \
        # Useful for troubleshooting
        iproute2 \
        iputils-ping && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* && \
    # https://docs.oracle.com/javase/7/docs/technotes/guides/net/properties.html
    # Java caches dns results forever, don't cache dns results forever:
    touch ${JAVA_HOME}/jre/lib/security/java.security && \
    sed -i '/networkaddress.cache.ttl/d' ${JAVA_HOME}/jre/lib/security/java.security && \
    sed -i '/networkaddress.cache.negative.ttl/d' ${JAVA_HOME}/jre/lib/security/java.security && \
    echo 'networkaddress.cache.ttl=0' >> ${JAVA_HOME}/jre/lib/security/java.security && \
    echo 'networkaddress.cache.negative.ttl=0' >> ${JAVA_HOME}/jre/lib/security/java.security && \
    # imagebuilder expects the directory to be created before VOLUME
    mkdir -p /var/lib/hive /.beeline ${HOME}/.beeline && \
    chown -R hive:hive ${HIVE_HOME} ${HADOOP_HOME} /var/lib/hive /.beeline ${HOME}/.beeline /etc/passwd $(readlink -f ${JAVA_HOME}/lib/security/cacerts) && \
    chmod -R u+rwx,g+rwx ${HIVE_HOME} ${HADOOP_HOME} /var/lib/hive /.beeline ${HOME}/.beeline /etc/passwd $(readlink -f ${JAVA_HOME}/lib/security/cacerts) && \
    # Update the path for all users so hive commands work
    echo "export PATH=$PATH" > /etc/profile.d/hive_path.sh

# All this should be done as the hive user to avoid duplicating files in layers
USER hive
WORKDIR /opt
RUN curl -L https://dlcdn.apache.org/hive/hive-${HIVE_VERSION}/apache-hive-${HIVE_VERSION}-bin.tar.gz | tar zxf - && \
    curl -L https://dlcdn.apache.org/hadoop/common/hadoop-${HADOOP_VERSION}/hadoop-${HADOOP_VERSION}.tar.gz | tar zxf - && \
    curl -L https://archive.apache.org/dist/tez/${TEZ_VERSION}/apache-tez-${TEZ_VERSION}-bin.tar.gz | tar xzf - && \
    mv apache-hive-${HIVE_VERSION}-bin/* ${HIVE_HOME} && \
    mv hadoop-${HADOOP_VERSION}/* ${HADOOP_HOME} && \
    mv apache-tez-${TEZ_VERSION}-bin/* ${TEZ_HOME} && \
    rm ${HIVE_HOME}/lib/postgresql-9.4.1208.jre7.jar && \
    # curl -o ${HIVE_HOME}/lib/postgresql-42.2.25.jre7.jar -L https://jdbc.postgresql.org/download/postgresql-42.2.25.jre7.jar && \
    curl -o ${HIVE_HOME}/lib/gcs-connector-hadoop3-${HADOOP_CONNECTORS_VERSION}-shaded.jar -L https://github.com/GoogleCloudDataproc/hadoop-connectors/releases/download/v${HADOOP_CONNECTORS_VERSION}/gcs-connector-hadoop3-${HADOOP_CONNECTORS_VERSION}-shaded.jar && \
    ln -s ${HIVE_HOME}/lib/gcs-connector-hadoop3-${HADOOP_CONNECTORS_VERSION}-shaded.jar /opt/hadoop/share/hadoop/common/gcs-connector-hadoop3-${HADOOP_CONNECTORS_VERSION}-shaded.jar && \
    # curl -o ${HIVE_HOME}/lib/postgres-socket-factory-${CLOUD_SQL_VERSION}-jar-with-driver-and-dependencies.jar -L https://storage.googleapis.com/cloud-sql-java-connector/v${CLOUD_SQL_VERSION}/postgres-socket-factory-${CLOUD_SQL_VERSION}-jar-with-driver-and-dependencies.jar && \
    curl -o ${HIVE_HOME}/lib/postgresql-42.2.25.jre7.jar -L https://jdbc.postgresql.org/download/postgresql-42.2.25.jre7.jar && \
    # Configure Hadoop AWS Jars to be available to hive
    # ln -s ${HADOOP_HOME}/share/hadoop/tools/lib/*aws* ${HIVE_HOME}/lib && \
    # Remove vulnerable Log4j version and install latest
    rm -f ${HADOOP_HOME}/share/hadoop/common/lib/slf4j-log4j12* && \
    rm -f ${HADOOP_HOME}/share/hadoop/common/lib/log4j* && \
    rm -f ${HADOOP_HOME}/share/hadoop/hdfs/lib/log4j* && \
    rm -f ${HADOOP_HOME}/share/hadoop/yarn/hadoop-yarn-applications-catalog-webapp-3.3.1.war && \
    rm -f ${HIVE_HOME}/lib/log4j-* && \
    curl -o ${HIVE_HOME}/lib/log4j-1.2-api-${LOG4J_VERSION}.jar ${LOG4J_LOCATION}/log4j-1.2-api/${LOG4J_VERSION}/log4j-1.2-api-${LOG4J_VERSION}.jar  && \
    curl -o ${HIVE_HOME}/lib/log4j-api-${LOG4J_VERSION}.jar ${LOG4J_LOCATION}/log4j-api/${LOG4J_VERSION}/log4j-api-${LOG4J_VERSION}.jar && \
    curl -o ${HIVE_HOME}/lib/log4j-core-${LOG4J_VERSION}.jar ${LOG4J_LOCATION}/log4j-core/${LOG4J_VERSION}/log4j-core-${LOG4J_VERSION}.jar && \
    curl -o ${HIVE_HOME}/lib/log4j-slf4j-impl-${LOG4J_VERSION}.jar ${LOG4J_LOCATION}/log4j-slf4j-impl/${LOG4J_VERSION}/log4j-slf4j-impl-${LOG4J_VERSION}.jar && \
    mkdir /tmp/hive && \
    chmod 777 /tmp/hive

COPY conf ${HIVE_HOME}/conf
COPY scripts/entrypoint.sh ${HIVE_HOME}/entrypoint.sh

RUN rm /opt/hadoop/etc/hadoop/core-site.xml && \
    ln -s /opt/hive/conf/hive-site.xml /opt/hadoop/etc/hadoop/core-site.xml

# to allow running as non-root
# RUN chown -R hive:hive ${HIVE_HOME} ${HADOOP_HOME} /var/lib/hive /.beeline ${HOME}/.beeline /etc/passwd $(readlink -f ${JAVA_HOME}/lib/security/cacerts) && \
#     chmod -R u+rwx,g+rwx ${HIVE_HOME} ${HADOOP_HOME} /var/lib/hive /.beeline ${HOME}/.beeline /etc/passwd $(readlink -f ${JAVA_HOME}/lib/security/cacerts)
#    chown 1002:0 ${HIVE_HOME}/entrypoint.sh && chmod +x ${HIVE_HOME}/entrypoint.sh

WORKDIR $HIVE_HOME
EXPOSE 9083

ENTRYPOINT ["sh", "-c", "/opt/hive/entrypoint.sh"]