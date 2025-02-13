package db

import (
    "context"
    "fmt"
    "time"
    "go.mongodb.org/mongo-driver/mongo"
    "go.mongodb.org/mongo-driver/mongo/options"
    "go.mongodb.org/mongo-driver/mongo/readpref"
    "github.com/globocom/huskyCI/api/log"
    "go.mongodb.org/mongo-driver/bson"
)
// Conn is the MongoDB connection variable.
var Conn *DB
// Collections names used in MongoDB.
var (
    RepositoryCollection         = "repository"
    SecurityTestCollection       = "securityTest"
    AnalysisCollection           = "analysis"
    UserCollection               = "user"
    AccessTokenCollection        = "accessToken"
    DockerAPIAddressesCollection = "dockerAPIAddresses"
)
// DB is the struct that represents mongo client.
type DB struct {
    Client *mongo.Client
}
const logActionConnect = "Connect"
const logActionReconnect = "autoReconnect"
const logInfoMongo = "DB"

// Database is the interface's database.
type Database interface {
    Insert(obj interface{}, collection string) error
    Search(filter interface{}, selectors []string, collection string, obj interface{}) 
error
    Update(filter interface{}, update interface{}, collection string) error
    UpdateAll(filter, update interface{}, collection string) error
    FindAndModify(filter, update interface{}, collection string, obj interface{}) 
error
    Upsert(filter interface{}, obj interface{}, collection string) error
    SearchOne(filter interface{}, selectors []string, collection string, obj 
interface{}) error
}
// Connect connects to MongoDB and returns the client.
func Connect(uri string) error {
    log.Info(logActionConnect, logInfoMongo, 21)
    client, err := mongo.NewClient(options.Client().ApplyURI(uri))
    if err != nil {
        log.Error(logActionConnect, logInfoMongo, 2001, err)
        return err
    }
    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()
    err = client.Connect(ctx)
    if err != nil {
        log.Error(logActionConnect, logInfoMongo, 2002, err)
        return err
    }
    err = client.Ping(ctx, readpref.Primary())
    if err != nil {
        log.Error(logActionConnect, logInfoMongo, 2002, err)
        return err
    }
    Conn = &DB{Client: client}
    go autoReconnect()
    return nil
}
// autoReconnect checks MongoDB's connection each second and, if an error is 
found, reconnects.
func autoReconnect() {
    log.Info(logActionReconnect, logInfoMongo, 22)
    for {
        err := Conn.Client.Ping(context.Background(), readpref.Primary())
        if err != nil {
            log.Error(logActionReconnect, logInfoMongo, 2003, err)
            Conn.Client.Disconnect(context.Background())
            if err == nil {
                log.Info(logActionReconnect, logInfoMongo, 23)
            } else {
                log.Error(logActionReconnect, logInfoMongo, 2004, err)
            }
        }
        time.Sleep(time.Second * 1)
    }
}
// Insert inserts a new document.
func (db *DB) Insert(obj interface{}, collection string) error {
    collectionRef := db.Client.Database("").Collection(collection)
    _, err := collectionRef.InsertOne(context.Background(), obj)
    return err
}
// Update updates a single document.
func (db *DB) Update(filter, update interface{}, collection string) error {
    collectionRef := db.Client.Database("").Collection(collection)
    _, err := collectionRef.UpdateOne(context.Background(), filter, update)
    return err
}
// UpdateAll updates all documents that match the query.
func (db *DB) UpdateAll(filter, update interface{}, collection string) error {
    collectionRef := db.Client.Database("").Collection(collection)
    _, err := collectionRef.UpdateMany(context.Background(), filter, update)
    return err
}
func (db *DB) FindAndModify(filter, update interface{}, collection string, obj 
interface{}) error {
    collectionRef := db.Client.Database("").Collection(collection)
    return collectionRef.FindOneAndUpdate(context.Background(), filter, 
update).Decode(obj)
}
// Search searches all documents that match the query. If selectors are present, the
return will be only the chosen fields.
func (db *DB) Search(filter interface{}, selectors []string, collection string, obj 
interface{}) error {
    collectionRef := db.Client.Database("").Collection(collection)
    opts := options.Find()
    if selectors != nil {
        opts.SetProjection(bson.M{selectors[0]: 1}) // This needs to be dynamically 
set
    }
    cursor, err := collectionRef.Find(context.Background(), filter, opts)
    if err != nil {
        return err
    }
    err = cursor.All(context.Background(), obj)
    return err
}
// Aggregation prepares a pipeline to aggregate.
func (db *DB) Aggregation(aggregation []bson.M, collection string) (interface{}, 
error) {
    collectionRef := db.Client.Database("").Collection(collection)
    cursor, err := collectionRef.Aggregate(context.Background(), aggregation)
    resp := []bson.M{}
    if err = cursor.All(context.Background(), &resp); err != nil {
        return nil, err
    }
    return resp, nil
}
// SearchOne searches for the first element that matches with the given query.
func (db *DB) SearchOne(filter interface{}, selectors []string, collection string, 
obj interface{}) error {
    collectionRef := db.Client.Database("").Collection(collection)
    opts := options.FindOne()
    if selectors != nil {
        opts.SetProjection(bson.M{selectors[0]: 1}) // This needs to be dynamically 
set
    }
    return collectionRef.FindOne(context.Background(), filter, opts).Decode(obj)
}
// Upsert inserts a document or updates it if it already exists.
func (db *DB) Upsert(filter interface{}, obj interface{}, collection string) error {
    collectionRef := db.Client.Database("").Collection(collection)
    opts := options.Update().SetUpsert(true)
    _, err := collectionRef.UpdateOne(context.Background(), filter, bson.M{"$set": 
obj}, opts)
    return err
