go mod init     example.com/web-service-gin
go: creating new go.mod: module     example.com/web-service-gin
go mod init     example.com/web-service-gin
go get .
go get: added     github.com/gin-gonic/gin v1.7.2
curl http://localhost:8080/albums
go run .
curl http://localhost:8080/albums     --include --header     "Content-Type: application/json"     --request "POST" --data     '{"id": "4","title": "The Modern Sound of Betty Carter","artist": "Betty Carter","price": 49.99}'
curl http://localhost:8080/albums     --header     "Content-Type: application/json"     --request "GET"
curl http://localhost:8080/albums/2
docker build -t web-service-gin .
docker run -p 8080:8080 web-service-gin
docker build -t web-service-gin .
docker ps
curl http://localhost:8080/albums
curl http://localhost:8080/albums
docker run -p 8080:8080 web-service-gin
docker ps
curl http://localhost:8080/albums
docker logs cd67862f2317
curl http://localhost:8080/albums
go run .
docker run -p 8080:8080 -v $(pwd)/data:/app/data web-service-gin
docker build -t web-service-gin .
curl http://0.0.0.0:8080/albums
docker run -p 8080:8080 web-service-gin
docker build -t web-service-gin .
docker run -p 8080:8080 web-service-gin
go test
curl http://0.0.0.0:8080/albums
docker ps
docker ps -a
go run .
docker run -p 8080:8080 -v /home/leonardo_cavalcanti_136/web-service-gin/my-data:/app/my-data web-service-gin
docker build -t web-service-gin .
docker ps
docker run -p 8080:8080 -v /home/leonardo_cavalcanti_136/web-service-gin/my-data:/app/my-data web-service-gin
docker rm 9f84d18
docker ps
docker ps 
docker build -t web-service-gin .
docker ps
docker run -p 8080:8080 -v /home/leonardo_cavalcanti_136/web-service-gin/my-data:/app/my-data web-service-gin
go test
curl http://localhost:8080/logs
curl http://localhost:8080/albums
curl http://localhost:8080/albums/1
curl -X POST -H "Content-Type: application/json" -d '{"id": "4", "title": "New Album", "artist": "New Artist", "price": 29.99}' http://localhost:8080/albums
curl -X PUT -H "Content-Type: application/json" -d '{"title": "Updated Album", "artist": "Updated Artist", "price": 39.99}' http://localhost:8080/albums/4
curl -X DELETE http://localhost:8080/albums/4
docker ps
docker build -t web-service-gin .
docker ps
docker run -p 8080:8080 -v /home/leonardo_cavalcanti_136/web-service-gin/my-data:/app/my-data web-service-gin
go get github.com/dgrijalva/jwt-go
go get github.com/stretchr/testify/assert
docker ps
go test
go test -v
git init 
git add.
git init 
git add.
git add .
git config --global user.name "LeonardoPCavalcanti"
git config --global user.email "leozinhopcavalcanti@hotmail.com"
git config --global --list
