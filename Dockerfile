#builder stage
FROM golang:1.23-alpine AS builder
ENV APPHOME=/app
WORKDIR $APPHOME
COPY . ./
RUN go mod download && go mod verify
RUN go build -o /main ./app/service.go

#final stage
FROM alpine:latest
RUN apk add --no-cache ca-certificates curl \
    && update-ca-certificates
ENV APPHOME=/app
WORKDIR $APPHOME
COPY --from=builder /main ./
RUN chmod +x ./main
EXPOSE 7467
CMD ["./main"]