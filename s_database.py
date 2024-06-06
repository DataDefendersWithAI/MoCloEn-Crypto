from pymongo import MongoClient,server_api

uri = "mongodb+srv://moclon.snjuttl.mongodb.net/?authSource=%24external&authMechanism=MONGODB-X509&retryWrites=true&w=majority&appName=MoClon"
client = MongoClient(uri,
                        tls=True,
                        tlsCertificateKeyFile='/home/apac/Stuff/secret/X509-cert-1713741244567756238.pem',
                        server_api=server_api.ServerApi('1')
                    )

db = client['testDB']
collection = db['testCol']
doc_count = collection.count_documents({})
print(doc_count)