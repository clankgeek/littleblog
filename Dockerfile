FROM golang:1.24-alpine AS builder
RUN apk add make musl-dev
WORKDIR /app
COPY . .
RUN make build