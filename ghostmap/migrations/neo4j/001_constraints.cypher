// GhostMap Neo4j constraints & indexes
// Modelo: Page, Endpoint, ApiOperation, GraphQLOperation, Param, JWT, Cookie,
//         User, Role, Upload, File, Bucket, Integration, Host
// Edges: NAVIGATES_TO, REDIRECTS_TO, CALLS, AUTH_BY, USES_PARAM, TRUSTS,
//        OWNED_BY_ROLE, UPLOADS_TO, INTEGRATES_WITH, CHAINS_INTO

CREATE CONSTRAINT page_id          IF NOT EXISTS FOR (n:Page)             REQUIRE n.id IS UNIQUE;
CREATE CONSTRAINT endpoint_id      IF NOT EXISTS FOR (n:Endpoint)         REQUIRE n.id IS UNIQUE;
CREATE CONSTRAINT api_id           IF NOT EXISTS FOR (n:ApiOperation)     REQUIRE n.id IS UNIQUE;
CREATE CONSTRAINT graphql_id       IF NOT EXISTS FOR (n:GraphQLOperation) REQUIRE n.id IS UNIQUE;
CREATE CONSTRAINT param_id         IF NOT EXISTS FOR (n:Param)            REQUIRE n.id IS UNIQUE;
CREATE CONSTRAINT jwt_id           IF NOT EXISTS FOR (n:JWT)              REQUIRE n.id IS UNIQUE;
CREATE CONSTRAINT cookie_id        IF NOT EXISTS FOR (n:Cookie)           REQUIRE n.id IS UNIQUE;
CREATE CONSTRAINT user_id          IF NOT EXISTS FOR (n:User)             REQUIRE n.id IS UNIQUE;
CREATE CONSTRAINT role_id          IF NOT EXISTS FOR (n:Role)             REQUIRE n.id IS UNIQUE;
CREATE CONSTRAINT upload_id        IF NOT EXISTS FOR (n:Upload)           REQUIRE n.id IS UNIQUE;
CREATE CONSTRAINT file_id          IF NOT EXISTS FOR (n:File)             REQUIRE n.id IS UNIQUE;
CREATE CONSTRAINT bucket_id        IF NOT EXISTS FOR (n:Bucket)           REQUIRE n.id IS UNIQUE;
CREATE CONSTRAINT integration_id   IF NOT EXISTS FOR (n:Integration)      REQUIRE n.id IS UNIQUE;
CREATE CONSTRAINT host_id          IF NOT EXISTS FOR (n:Host)             REQUIRE n.id IS UNIQUE;

CREATE INDEX endpoint_project_idx  IF NOT EXISTS FOR (n:Endpoint) ON (n.project_id);
CREATE INDEX endpoint_path_idx     IF NOT EXISTS FOR (n:Endpoint) ON (n.host, n.path, n.method);
CREATE INDEX page_url_idx          IF NOT EXISTS FOR (n:Page)     ON (n.url);
CREATE INDEX role_project_idx      IF NOT EXISTS FOR (n:Role)     ON (n.project_id);
