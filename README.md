# Authentication microservice
Authentication microservice that delivers a JWT upon receiving correct credentials.
Here, users are stored in a Neo4J database.

## Configuration
The following environment variables must be provided to the container to function properly:

| Variable | Description |
| --- | --- |
| JWT_SECRET | The secret used in the JWT |
| NEO4J_URL| The URL of the Neo4J instance |
| NEO4J_USERNAME| Username to access the Neo4J instance |
| NEO4J_PASSWORD | The password for the Neo4J instance |
