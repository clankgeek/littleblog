FROM golang:1.24-alpine AS builder
RUN apk add gcc make musl-dev
WORKDIR /app
COPY . .
RUN make build
