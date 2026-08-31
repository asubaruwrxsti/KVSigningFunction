FROM golang:1.25.1 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /handler .

FROM mcr.microsoft.com/azure-functions/base:4
# This is the generic Functions host image; it works for Go custom handlers.
ENV AzureWebJobsScriptRoot=/home/site/wwwroot
ENV AzureFunctionsJobHost__Logging__Console__IsEnabled=true

COPY --from=build /handler /home/site/wwwroot/handler
COPY host.json /home/site/wwwroot/host.json
COPY issue /home/site/wwwroot/issue

RUN chmod +x /home/site/wwwroot/handler