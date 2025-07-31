/* eslint-disable @typescript-eslint/no-non-null-assertion */
import {
	LOG_2_ID,
	LogEntryResponse,
} from '@mapistry/take-home-challenge-shared';
import { Uuid } from '../../domain/entities/Uuid';
import { Database, LogEntriesRecord } from '../../shared/database';
import { LogEntriesService } from './LogEntriesService';

describe('LogEntriesService', () => {
	const subject = new LogEntriesService();

	describe('getLogEntries', () => {
		let result: LogEntryResponse[];

		beforeAll(async () => {
			result = await subject.getLogEntries(LOG_2_ID);
		});

		it('returns all of the log entries for the given log id', async () => {
			expect(result).toHaveLength(1);
		});

		it('only returns log entries for the given log id', async () => {
			expect(result.every((le) => le.logId === LOG_2_ID)).toBeTruthy();
		});
	});

	describe('createLogEntry', () => {
		const newEntry = {
			logDate: '2024-01-01',
			logValue: 23,
		};
		let result: LogEntryResponse;

		beforeAll(async () => {
			result = await subject.createLogEntry(LOG_2_ID, newEntry);
		});

		it('creates a new log entry', async () => {
			const allEntries = await subject.getLogEntries(LOG_2_ID);
			expect(allEntries).toHaveLength(2);
		});

		it('returns the new log entry with an id', async () => {
			expect(result.logDate).toEqual(new Date(newEntry.logDate));
			expect(result.logValue).toEqual(newEntry.logValue);
			expect(result.id).toBeDefined();
		});
	});

	describe('deleteLogEntry', () => {
		let entryToDelete: LogEntriesRecord | undefined;
		let result: string;

		beforeAll(async () => {
			[entryToDelete] = await Database.getAllLogEntries(LOG_2_ID);
			result = await subject.deleteLogEntry(LOG_2_ID, entryToDelete!.id);
		});

		it('deletes the log entry for the given id', async () => {
			const allEntries = await subject.getLogEntries(LOG_2_ID);
			expect(allEntries).toHaveLength(1);
			expect(
				allEntries.find((le) => le.id === entryToDelete!.id)
			).toBeFalsy();
		});

		it('returns the deleted log entry id', () => {
			expect(result).toBe(entryToDelete!.id);
		});
	});

	describe('updateLogEntry', () => {
		let entryToUpdate: LogEntriesRecord | undefined;
		let result: LogEntryResponse;

		beforeAll(async () => {
			[entryToUpdate] = await Database.getAllLogEntries(LOG_2_ID);
			const updateData = {
				id: entryToUpdate!.id as unknown as Uuid,
				logId: LOG_2_ID,
				logDate: '2024-01-02',
				logValue: 30,
			};
			result = await subject.updateLogEntry(updateData);
		});

		it('updates the log entry with the given data', async () => {
			const allEntries = await subject.getLogEntries(LOG_2_ID);
			expect(allEntries).toHaveLength(1);
			expect(new Date(allEntries[0].logDate).toISOString()).toEqual(
				new Date('2024-01-02').toISOString()
			);
			expect(allEntries[0].logValue).toEqual(30);
		});

		it('returns the updated log entry', () => {
			expect(result.id).toBe(entryToUpdate!.id);
			expect(new Date(result.logDate).toISOString()).toEqual(
				new Date('2024-01-02').toISOString()
			);
			expect(result.logValue).toEqual(30);
		});
	});
});
