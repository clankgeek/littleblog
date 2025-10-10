FROM golang:1.25-alpine AS builder
RUN apk add gcc make musl-dev
WORKDIR /app
COPY . .
RUN make build
