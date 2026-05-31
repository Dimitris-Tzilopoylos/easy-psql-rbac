export class ForbiddenError extends Error {
  status: 403;
  constructor(message?: string) {
    super(message);
    this.status = 403;
  }
}
