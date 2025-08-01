import {
  LogEntryRequest,
  LogEntryResponse,
  EditLogEntryRequest,
} from '@mapistry/take-home-challenge-shared';
import { LogEntry } from '../../domain/entities/LogEntry';

export class LogEntriesApiMapper {
  public toResponse(logEntry: LogEntry): LogEntryResponse {
    return {
      id: logEntry.id.toString(),
      logId: logEntry.logId,
      logDate: logEntry.logDate,
      logValue: logEntry.logValue,
    };
  }

  public fromCreateRequest(
    logId: string,
    createLogEntry: LogEntryRequest
  ): LogEntry {
    return LogEntry.create({
      logId,
      logDate: new Date(createLogEntry.logDate),
      logValue: createLogEntry.logValue,
    });
  }

  public fromUpdateRequest(updateLogEntry: EditLogEntryRequest): LogEntry {
    return LogEntry.update({
      id: updateLogEntry.id,
      logId: updateLogEntry.logId,
      logDate: new Date(updateLogEntry.logDate),
      logValue: updateLogEntry.logValue,
    });
  }
}
