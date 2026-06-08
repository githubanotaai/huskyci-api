# Dockerfile used to create "huskyci/pnpmaudit" image

FROM node:alpine

RUN apk update && apk upgrade \
	&& apk add --no-cache alpine-sdk bash openssh-client \
	&& apk add git

RUN npm install -g pnpm@11.5.2
RUN wget -O jq https://github.com/stedolan/jq/releases/download/jq-1.5/jq-linux64
RUN chmod +x ./jq
RUN cp jq /usr/bin
