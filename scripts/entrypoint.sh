#!/bin/sh

export HADOOP_CLASSPATH=${HADOOP_HOME}/share/hadoop/tools/lib/aws-java-sdk-bundle-1.11.375.jar:${HADOOP_HOME}/share/hadoop/tools/lib/hadoop-aws-${HADOOP_VERSION}.jar
export HIVE_OPTS="${HIVE_OPTS} --hiveconf metastore.root.logger=${HIVE_LOGLEVEL},console "
export PATH=${HIVE_HOME}/bin:${HADOOP_HOME}/bin:$PATH

set +e
if schematool -dbType derby -info -verbose; then
    echo "Hive metastore schema verified."
else
    if schematool -dbType derby -initSchema -verbose; then
        echo "Hive metastore schema created."
    else
        echo "Error creating hive metastore: $?"
    fi
fi
set -e

hive --service metastore
