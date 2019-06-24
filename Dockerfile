FROM openjdk:8u212-jre

WORKDIR /opt

ENV HADOOP_HOME=/opt/hadoop-2.9.2
ENV HIVE_HOME=/opt/apache-hive-2.3.5-bin
# Include additional jars
ENV HADOOP_CLASSPATH=/opt/hadoop-2.9.2/share/hadoop/tools/lib/aws-java-sdk-bundle-1.11.199.jar:/opt/hadoop-2.9.2/share/hadoop/tools/lib/hadoop-aws-2.9.2.jar

RUN apt-get update && \
    curl -L https://www-us.apache.org/dist/hive/hive-2.3.5/apache-hive-2.3.5-bin.tar.gz | tar zxf - && \
    curl -L https://www-us.apache.org/dist/hadoop/common/hadoop-2.9.2/hadoop-2.9.2.tar.gz | tar zxf -

COPY conf ${HIVE_HOME}/conf

RUN groupadd -r hive --gid=1000 && \
    useradd -r -g hive --uid=1000 -d ${HIVE_HOME} hive && \
    chown hive:hive -R ${HIVE_HOME}

USER hive
WORKDIR $HIVE_HOME
EXPOSE 9083

ENTRYPOINT ["bin/hive"]
CMD ["--service", "metastore"]
