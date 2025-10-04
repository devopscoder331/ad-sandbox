FROM golang:1.21-alpine AS builder

WORKDIR /app

# Копируем go.mod и go.sum для кэширования зависимостей
COPY ./br-app/go.mod ./br-app/go.sum ./
RUN go mod download && go mod verify

# Копируем исходный код
COPY ./br-app/ ./

# Собираем приложение
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o main .

# Финальная стадия с минимальным образом
FROM alpine:latest

RUN apk --no-cache add ca-certificates
WORKDIR /root/

# Копируем собранный бинарник из builder стадии
COPY --from=builder /app/main .

# Команда по умолчанию
CMD ["./main"]