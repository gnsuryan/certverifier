#!/bin/bash

CURR_DIR=$(pwd)

if [ -z $JAVA_HOME ];
then
 echo "JAVA_HOME not set"
 exit 1
fi

OUTPUT_DIR=$CURR_DIR/output
mkdir -p $OUTPUT_DIR

echo "cleaning output dir..."
rm -rf $OUTPUT_DIR/*


if [ ! -f "$JAVA_HOME/bin/javac" ]
then
  echo "invalid JAVA_HOME set: $JAVA_HOME. Set JAVA_HOME correctly and try again."
  exit 1 
fi

echo "compiling..."
$JAVA_HOME/bin/javac -classpath $(printf %s: $CURR_DIR/lib/*.jar) -d $OUTPUT_DIR $CURR_DIR/src/*.java $CURR_DIR/test/*.java

if [ $? != 0 ];
then
 echo "compilation failed"
 exit 1
fi

echo "running validation program ..."
$JAVA_HOME/bin/java -classpath $(printf %s: $CURR_DIR/lib/*.jar):$OUTPUT_DIR ValidateSSLCertMain "$1" "$2" "$3" "$4" "$5" "$6" "$7" "$8"
