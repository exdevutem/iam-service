import { Catch, HttpException, Logger } from '@nestjs/common';
import type { ArgumentsHost, ExceptionFilter } from '@nestjs/common';
import type { Request, Response } from 'express';

@Catch()
export class HttpExceptionFilter implements ExceptionFilter {
  private readonly logger = new Logger(HttpExceptionFilter.name);
  catch(exception: unknown, host: ArgumentsHost) {
    const ctx = host.switchToHttp();
    const response = ctx.getResponse<Response>();
    const request = ctx.getRequest<Request>();
    const status =
      exception instanceof HttpException ? exception.getStatus() : 500;
    if (status >= 500)
      this.logger.error(
        JSON.stringify({
          code: 'REQUEST_FAILED',
          requestId: response.locals.requestId,
          method: request.method,
          status,
        }),
      );
    // Do not log URLs, bodies, raw errors or database credentials.
    const body =
      exception instanceof HttpException && status < 500
        ? exception.getResponse()
        : {
            message:
              status === 503
                ? 'Servicio no disponible'
                : 'Error interno del servidor',
          };
    response.status(status).json({
      ...(typeof body === 'string' ? { message: body } : body),
      statusCode: status,
      requestId: response.locals.requestId,
    });
  }
}
