import {
  Injectable,
  NestInterceptor,
  ExecutionContext,
  CallHandler,
  HttpException,
  BadRequestException,
} from '@nestjs/common';
import { Observable, throwError } from 'rxjs';
import { catchError, map } from 'rxjs/operators';

@Injectable()
export class ResponseInterceptor implements NestInterceptor {
  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    return next.handle().pipe(
      map((data) => ({
        status: 'success',
        data,
      })),
      catchError((error) => {
        if (error instanceof HttpException) {
          const { message, statusCode } = error.getResponse() as {
            message: string;
            statusCode: number;
          };
          return throwError(
            () =>
              new BadRequestException({
                status: 'error',
                errorCode: `HTTP_${statusCode}`,
                errorMessage: message,
              }),
          );
        } else {
          return throwError(
            () =>
              new BadRequestException({
                status: 'error',
                errorCode: 'UNKNOWN_ERROR',
                errorMessage: 'Unknown error occurred',
              }),
          );
        }
      }),
    );
  }
}
