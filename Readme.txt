pip install pyspark

//Hay que tener docker instalado
//Para que docker vaya bien hay que actualizar tu Linux en windows
wsl --version
wsl.exe --update

docker pull confluentinc/cp-kafka
docker pull zookeeper

docker run -d --name zookeeper -p 2181:2181 zookeeper
docker run -d --name kafka -p 9093:9093 --link zookeeper:zookeeper -e KAFKA_ZOOKEEPER_CONNECT=zookeeper:2181 -e KAFKA_ADVERTISED_LISTENERS=PLAINTEXT://localhost:9093 -e KAFKA_LISTENER_SECURITY_PROTOCOL=PLAINTEXT -e KAFKA_LISTENER_PORT=9093 -e KAFKA_LISTENER_NAME=PLAINTEXT confluentinc/cp-kafka

docker ps

pip install kafka-python

// Prueba de que si funciona: docker exec -it kafka kafka-console-producer --topic mi-tema --bootstrap-server localhost:9093



