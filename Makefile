db-up:
	docker-compose --profile=db --env-file=.env up -d --force-recreate

db-migrate:
	npm run db:migrate:dev

app-start-dev:
	npm run start:dev

app-build-image:
	docker-compose --profile=build-local build

app-up:
	docker-compose  --profile=app up -d --force-recreate

jwt-key-generate:
	ssh-keygen -t rsa -b 4096 -m PEM -f jwt/jwt.key
	openssl rsa -in jwt/jwt.key -pubout -outform PEM -out jwt/jwt.key.pub
