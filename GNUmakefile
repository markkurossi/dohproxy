
NAME := DoHProxy

all:
	@echo "Targets: deploy delete"

deploy:
	gcloud functions deploy $(NAME) --runtime go119 --trigger-http

delete:
	gcloud functions delete $(NAME)
