const express = require("express");
const { expressjwt: jwt } = require("express-jwt");
const { createLogger, format, transports } = require("winston");
const jsonwebtoken = require("jsonwebtoken");
const client = require("prom-client");

const app = express();

// Chave secreta para assinatura – em produção, use variável de ambiente
const SECRET_KEY = process.env.SECRET_KEY || "edu_learn_secret";

// Logger estruturado em JSON
const logger = createLogger({
  level: "info",
  format: format.combine(
    format.timestamp({ format: "YYYY-MM-DD HH:mm:ss" }),
    format.json()
  ),
  transports: [new transports.Console()]
});

// Métricas padrão do Node.js: CPU, memória, event loop etc.
client.collectDefaultMetrics();

// Histograma para medir duração das requisições
const httpRequestDuration = new client.Histogram({
  name: "http_request_duration_seconds",
  help: "Duração das requisições HTTP em segundos",
  labelNames: ["method", "route", "status_code"],
  buckets: [0.1, 0.5, 1, 2.5, 5]
});

app.use(express.json());

// Middleware que registra a duração de cada requisição
app.use((req, res, next) => {
  const start = Date.now();

  res.on("finish", () => {
    const delta = (Date.now() - start) / 1000;

    httpRequestDuration
      .labels(req.method, req.path, String(res.statusCode))
      .observe(delta);
  });

  next();
});

// Endpoint público para emissão de token
app.get("/token", (req, res) => {
  const user = req.query.user || "guest";
  const role = req.query.role || "student";

  const payload = { sub: user, role };

  const token = jsonwebtoken.sign(payload, SECRET_KEY, {
    expiresIn: "1h"
  });

  logger.info("Token emitido", {
    user,
    role
  });

  res.json({ token });
});

// Middleware de proteção JWT para rotas /users
app.use("/users", jwt({
  secret: SECRET_KEY,
  algorithms: ["HS256"]
}));

// Rota protegida: lista de usuários
app.get("/users", (req, res) => {
  logger.info("Acesso a /users", {
    user: req.auth.sub,
    role: req.auth.role
  });

  res.json([
    { id: 1, name: "Alice Silva", role: req.auth.role },
    { id: 2, name: "Prof. Bob Santos", role: req.auth.role }
  ]);
});

// Endpoint que expõe métricas compatíveis com Prometheus
app.get("/metrics", async (req, res) => {
  res.set("Content-Type", client.register.contentType);
  res.end(await client.register.metrics());
});

// Tratamento de erros de autenticação e outros erros
app.use((err, req, res, next) => {
  if (err.name === "UnauthorizedError") {
    logger.warn("Falha de autenticação", {
      method: req.method,
      route: req.path,
      statusCode: 401,
      error: err.message
    });

    return res.status(401).json({
      message: "Token inválido ou ausente"
    });
  }

  logger.error("Erro interno da aplicação", {
    method: req.method,
    route: req.path,
    statusCode: 500,
    error: err.message
  });

  return res.status(500).json({
    message: "Erro interno do servidor"
  });
});

// Inicia o servidor
const PORT = process.env.PORT || 3001;

app.listen(PORT, () => {
  console.log(`EduLearn User Service rodando na porta ${PORT}`);
});