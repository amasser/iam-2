


build:
	go build github.com/wanliu/iam/cmd/iamserver

run: build
	./iamserver

init: 
	@rm iam.db
	@./iamserver initdb 