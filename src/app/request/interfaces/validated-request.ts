import { Request } from 'express';
import RequestUserInterface from '@/app/request/interfaces/request-user.Interface';

export interface ValidatedRequest extends Request {
  user: RequestUserInterface;
}
