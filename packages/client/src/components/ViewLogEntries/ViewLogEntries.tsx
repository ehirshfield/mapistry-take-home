import { useCallback, useState } from 'react';
import styled from 'styled-components';
import { useLastVisitedLog } from '../../hooks/useLastVisitedLog';
import { useLogEntries } from '../../hooks/useLogEntries';
import { createLogEntry, updateLogEntry } from '../../shared/apiClient/logsApi';
import { Error } from '../shared/Error';
import { Loading } from '../shared/Loading';
import { LogEntryModal } from '../LogEntryModal/LogEntryModal';
import { ViewLogEntriesEmptyPage } from './ViewLogEntriesEmptyPage';
import { ViewLogEntriesHeader } from './ViewLogEntriesHeader';
import { ViewLogEntriesTable } from './ViewLogEntriesTable';
import {
	DateLike,
	EditLogEntryRequest,
} from '@mapistry/take-home-challenge-shared';
import { Uuid } from '@mapistry/take-home-challenge-server/src/domain/entities/Uuid';

export type LogEntryFormValues = {
	logDate: DateLike;
	logValue: number;
};

const Container = styled.div`
	height: 100vh;
`;

export function ViewLogEntries() {
	const { lastVisitedLog } = useLastVisitedLog();
	const { logEntries, error, isLoading, refreshLogEntries } = useLogEntries({
		logId: lastVisitedLog.id,
	});
	const [isCreateEntryOpen, setIsCreateEntryOpen] = useState(false);
	const [isEditEntryOpen, setIsEditEntryOpen] = useState(false);
	const [initialEditValues, setInitialEditValues] =
		useState<EditLogEntryRequest>({
			id: '' as unknown as Uuid,
			logId: '',
			logDate: '',
			logValue: 0,
		});

	const handleAddNew = useCallback(async () => {
		setIsCreateEntryOpen(true);
	}, []);

	const handleCloseModal = useCallback(() => {
		setIsCreateEntryOpen(false);
		setIsEditEntryOpen(false);
	}, [setIsCreateEntryOpen, setIsEditEntryOpen]);

	const handleCreateLogEntry = useCallback(
		async (logEntry) => {
			await createLogEntry({ logId: lastVisitedLog.id, logEntry });
			setIsCreateEntryOpen(false);
			refreshLogEntries();
		},
		[lastVisitedLog, refreshLogEntries, setIsCreateEntryOpen]
	);

	const handleEditLogEntry = useCallback(
		async (logEntry) => {
			await updateLogEntry(logEntry);
			setIsEditEntryOpen(false);
			refreshLogEntries();
		},
		[refreshLogEntries, setIsEditEntryOpen]
	);

	function content() {
		if (isLoading) {
			return <Loading />;
		}
		if (error) {
			return (
				<Error message='Sorry, there was an error loading the log entries.' />
			);
		}
		return logEntries.length ? (
			<ViewLogEntriesTable
				logId={lastVisitedLog.id}
				setIsEditEntryOpen={setIsEditEntryOpen}
				setInitialEditValues={setInitialEditValues}
			/>
		) : (
			<ViewLogEntriesEmptyPage />
		);
	}

	return (
		<Container>
			{isCreateEntryOpen && (
				<LogEntryModal
					header='Create Log Entry'
					handleClose={handleCloseModal}
					handleSubmit={handleCreateLogEntry}
				/>
			)}
			{isEditEntryOpen && (
				<LogEntryModal
					header='Edit Log Entry'
					initialValues={initialEditValues}
					handleClose={handleCloseModal}
					handleSubmit={handleEditLogEntry}
				/>
			)}
			<ViewLogEntriesHeader
				onAddNew={handleAddNew}
				logName={lastVisitedLog.name}
			/>
			{content()}
		</Container>
	);
}
