/** Expected failures, each with an HTTP status hint and a stable, documented code. */
export class AppError extends Error {
  constructor(
    readonly status: 400 | 401 | 404 | 409,
    readonly code: string,
    message: string,
    readonly errors: readonly { path: string; message: string }[] = [],
  ) {
    super(message);
    this.name = new.target.name;
  }
}

export const unauthorized = () =>
  new AppError(401, 'auth.invalid_key', 'Send a valid API key as "Authorization: Bearer wit_...".');

export const notFound = (what: string) =>
  new AppError(404, `${what}.not_found`, `That ${what} does not exist.`);
