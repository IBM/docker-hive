FROM openjdk:8u212-jre

WORKDIR /opt

ENV HADOOP_HOME=/opt/hadoop-3.1.3
ENV HIVE_HOME=/opt/apache-hive-metastore-3.0.0-bin
# Include additional jars
ENV HADOOP_CLASSPATH=/opt/hadoop-3.1.3/share/hadoop/tools/lib/aws-java-sdk-bundle-1.11.271.jar:/opt/hadoop-3.1.3/share/hadoop/tools/lib/hadoop-aws-3.1.3.jar

RUN curl -L https://www-us.apache.org/dist/hive/hive-standalone-metastore-3.0.0/hive-standalone-metastore-3.0.0-bin.tar.gz | tar zxf - && \
    curl -L https://www-us.apache.org/dist/hadoop/common/hadoop-3.1.3/hadoop-3.1.3.tar.gz | tar zxf - && \
    rm -f ${HIVE_HOME}/lib/guava-19.0.jar && \
    cp ${HADOOP_HOME}/share/hadoop/common/lib/guava-27.0-jre.jar ${HIVE_HOME}/lib/
    
COPY conf/metastore-site.xml ${HIVE_HOME}/conf

RUN groupadd -r hive --gid=1000 && \
    useradd -r -g hive --uid=1000 -d ${HIVE_HOME} hive && \
    chown hive:hive -R ${HIVE_HOME}

USER hive
WORKDIR $HIVE_HOME
EXPOSE 9083

ENTRYPOINT ["bin/start-metastore"]
