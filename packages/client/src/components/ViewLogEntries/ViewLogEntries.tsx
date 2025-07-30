import { useCallback, useState } from 'react';
import styled from 'styled-components';
import { useLastVisitedLog } from '../../hooks/useLastVisitedLog';
import { useLogEntries } from '../../hooks/useLogEntries';
import { createLogEntry } from '../../shared/apiClient/logsApi';
import { Error } from '../shared/Error';
import { Loading } from '../shared/Loading';
import { LogEntryModal } from '../LogEntryModal/LogEntryModal';
import { ViewLogEntriesEmptyPage } from './ViewLogEntriesEmptyPage';
import { ViewLogEntriesHeader } from './ViewLogEntriesHeader';
import { ViewLogEntriesTable } from './ViewLogEntriesTable';

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
			console.log('Edit log entry:', logEntry);
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
			/>
		) : (
			<ViewLogEntriesEmptyPage />
		);
	}

	return (
		<Container>
			{isCreateEntryOpen && (
				<LogEntryModal
					mode='create'
					handleClose={handleCloseModal}
					handleSubmit={handleCreateLogEntry}
				/>
			)}
			{isEditEntryOpen && (
				<LogEntryModal
					mode='edit'
					initialValues={{ logDate: '', logValue: 0 }}
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
