from pyspark.sql import SparkSession
from pyspark.sql.functions import split, col

spark = SparkSession.builder.appname('SIEM').getOrCreate()

logs_df = spark.readstream.format('kafka')