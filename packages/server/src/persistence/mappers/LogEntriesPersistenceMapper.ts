import { LogEntry } from '../../domain/entities/LogEntry';
import { LogEntriesRecord } from '../../shared/database';
import { Uuid } from '../../domain/entities/Uuid';

export class LogEntriesPersistenceMapper {
  static toPersistence(logEntry: LogEntry): LogEntriesRecord {
    return {
      id: logEntry.id.toString(),
      logId: logEntry.logId,
      logDate: logEntry.logDate,
      logValue: logEntry.logValue,
    };
  }

  static fromPersistence(logEntriesRecord: LogEntriesRecord): LogEntry {
    return LogEntry.createFromPersistence(
      logEntriesRecord,
      logEntriesRecord.id
    );
  }

  static fromUpdatePersistence(logEntriesRecord: LogEntriesRecord): LogEntry {
    return LogEntry.createFromPersistence(
      logEntriesRecord,
      logEntriesRecord.id
    );
  }
}
