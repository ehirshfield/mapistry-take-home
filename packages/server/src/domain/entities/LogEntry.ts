import { ValidationError } from '../../shared/errors';
import { Entity } from './Entity';
import { Uuid } from './Uuid';

interface LogEntryProps {
  logDate: Date;
  logValue: number;
  logId: string;
}

type CreateLogEntryProps = LogEntryProps;
type UpdateLogEntryProps = LogEntryProps & { id: Uuid };

export class LogEntry extends Entity<LogEntryProps> {
  static createFromPersistence(props: LogEntryProps, id: string) {
    return new LogEntry(props, Uuid.create(id));
  }

  static create(createLogEntryProps: CreateLogEntryProps) {
    if (!this.isValid(createLogEntryProps)) {
      throw new ValidationError(
        'Cannot create log entry. Props are not valid.'
      );
    }
    return new LogEntry(createLogEntryProps);
  }

  static update(updateLogEntryProps: UpdateLogEntryProps) {
    if (!this.isValid(updateLogEntryProps)) {
      throw new ValidationError(
        'Cannot update log entry. Props are not valid.'
      );
    }
    return new LogEntry(updateLogEntryProps, updateLogEntryProps.id);
  }

  private static isValid(createLogEntryProps: CreateLogEntryProps): boolean {
    return typeof createLogEntryProps.logValue === 'number';
  }

  get logDate() {
    return this.props.logDate;
  }

  get logValue() {
    return this.props.logValue;
  }

  get logId() {
    return this.props.logId;
  }
}
