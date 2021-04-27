FROM azul/zulu-openjdk-debian:11.0.10

WORKDIR /opt

ENV HADOOP_HOME=/opt/hadoop-2.10.1
ENV HIVE_HOME=/opt/apache-hive-2.3.8-bin
# Include additional jars
ENV HADOOP_CLASSPATH=/opt/hadoop-2.10.1/share/hadoop/tools/lib/aws-java-sdk-bundle-1.11.271.jar:/opt/hadoop-2.10.1/share/hadoop/tools/lib/hadoop-aws-2.10.1.jar

RUN apt-get update && \
    apt-get -qqy install curl && \
    curl -L https://www-us.apache.org/dist/hive/hive-2.3.8/apache-hive-2.3.8-bin.tar.gz | tar zxf - && \
    curl -L https://www-us.apache.org/dist/hadoop/common/hadoop-2.10.1/hadoop-2.10.1.tar.gz | tar zxf - && \
    apt-get install --only-upgrade openssl libssl1.1 && \
    apt-get install -y libk5crypto3 libkrb5-3 libsqlite3-0

RUN rm ${HIVE_HOME}/lib/postgresql-9.4.1208.jre7.jar

RUN curl -L https://jdbc.postgresql.org/download/postgresql-9.4.1212.jre7.jar > ${HIVE_HOME}/lib/postgresql-9.4.1212.jre7.jar

COPY conf ${HIVE_HOME}/conf

RUN groupadd -r hive --gid=1000 && \
    useradd -r -g hive --uid=1000 -d ${HIVE_HOME} hive && \
    chown hive:hive -R ${HIVE_HOME}

USER hive
WORKDIR $HIVE_HOME
EXPOSE 9083

ENTRYPOINT ["bin/hive"]
CMD ["--service", "metastore"]