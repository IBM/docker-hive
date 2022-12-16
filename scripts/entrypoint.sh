#!/bin/bash

#
# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The ASF licenses this file to You under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
# the License.  You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

set -x

# Passable arguments
: "${DB_DRIVER:=derby}"
: "${HIVE_LOGLEVEL:=INFO}"
: "${SERVICE_NAME:=metastore}"
# And SERVICE_OPTS
# To change db for metastore
# SERVICE_OPTS: '-Xmx1G -Djavax.jdo.option.ConnectionDriverName=org.postgresql.Driver
#                 -Djavax.jdo.option.ConnectionURL=jdbc:postgresql://postgres:5432/metastore_db
#                 -Djavax.jdo.option.ConnectionUserName=hive
#                 -Djavax.jdo.option.ConnectionPassword=password'
# Hiveserver2:
# HIVE_SERVER2_THRIFT_PORT: 10000
# SERVICE_OPTS: '-Xmx1G -Dhive.metastore.uris=thrift://metastore:9083'

SERVICE_OPTS="-Xmx1G -Djavax.jdo.option.ConnectionDriverName=org.apache.derby.jdbc.EmbeddedDriver"

SKIP_SCHEMA_INIT="${IS_RESUME:-false}"

# This can be simplified in hive >=4.0 with -initOrUpgradeSchema
function initialize_hive {
  if "$HIVE_HOME/bin/schematool" -dbType "$DB_DRIVER" -info -verbose; then
    echo "Hive metastore schema verified."
  else
    if "$HIVE_HOME"/bin/schematool -dbType "$DB_DRIVER" -initSchema -verbose; then
        echo "Hive metastore schema created."
    else
        echo "Error creating hive metastore: $?"
        exit 1
    fi
  fi
}

export HIVE_CONF_DIR=$HIVE_HOME/conf
export HADOOP_CLIENT_OPTS="$HADOOP_CLIENT_OPTS -Xmx1G $SERVICE_OPTS"

if [[ "${SKIP_SCHEMA_INIT}" == "false" ]]; then
  # handles schema initialization
  initialize_hive
fi

if [ "${SERVICE_NAME}" == "hiveserver2" ]; then
  export HADOOP_CLASSPATH="$TEZ_HOME/*:$TEZ_HOME/lib/*:$HADOOP_CLASSPATH"
elif [ "${SERVICE_NAME}" == "metastore" ]; then
  export METASTORE_PORT="${METASTORE_PORT:-9083}"
  export HIVE_OPTS="${HIVE_OPTS} --hiveconf metastore.root.logger=${HIVE_LOGLEVEL},console"
fi

exec "$HIVE_HOME/bin/hive" --skiphadoopversion --skiphbasecp --service "$SERVICE_NAME"