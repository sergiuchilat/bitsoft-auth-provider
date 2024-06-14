import { ResponseMetaInterface } from '@/app/response/interfaces/response-meta.interface';

export interface ResponsePaginatedDataInterface<T> {
  data: T[];
  meta: ResponseMetaInterface;
}
