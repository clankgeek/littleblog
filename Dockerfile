FROM golang:1.27-alpine AS builder
RUN apk add gcc make musl-dev
WORKDIR /app
COPY . .
RUN make build
