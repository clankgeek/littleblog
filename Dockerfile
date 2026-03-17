FROM golang:1.26-alpine AS builder
RUN apk add gcc make musl-dev
WORKDIR /app
COPY . .
RUN make build
