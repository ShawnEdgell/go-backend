# go-backend

This project is a basic Go backend designed to be reusable for future projects, primarily SvelteKit and React websites. It leverages the Gin web framework and GORM for database interactions.

## Technologies

- **Go**: The programming language used for building the backend.
- **Gin**: A high-performance HTTP web framework for Go.
- **GORM**: An ORM library for Go.
- **PostgreSQL**: The relational database used for storing data.
- **Docker**: Containerization tool (optional).
- **CORS Middleware**: Middleware for handling Cross-Origin Resource Sharing.
- **JWT (JSON Web Tokens)**: For secure authentication and authorization.

## Features

- Basic API setup with Gin
- Database connection using GORM
- Basic CRUD operations
- Middleware for logging, recovery, and CORS handling
- User registration and login with hashed passwords
- JWT-based authentication and authorization
- Protected routes that require JWT tokens