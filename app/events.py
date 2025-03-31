from graphframes import GraphFrame

edges = spark.createDataFrame([
    ("firewall", "ids"),
    ("ids", "webserver"),
    ("webserver", "endpoint"),
], ["src", "dst"])

nodes = logs_df.select("source").distinct().withColumnRenamed("source", "id")
graph = GraphFrame(nodes, edges)

# Encontrar patrones sospechosos
attack_paths = graph.find("(a)-[e]->(b)").filter("a.id == 'firewall' AND b.id == 'endpoint'")
attack_paths.show()
