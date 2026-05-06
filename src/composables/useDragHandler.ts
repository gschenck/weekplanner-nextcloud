// Coordinates persistence after a drag-and-drop change.
//
// Drags can move tasks between any two lists: day columns, weekend columns,
// or custom columns. vuedraggable emits a `change` event from each affected
// list, but the handler doesn't get to inspect which lists were involved.
// To keep server state consistent we always save both the week and the
// custom columns — debouncing collapses the burst of events into one network
// write per side.
//
// Saving only the week (the previous behaviour, gated on recurring-definition
// changes) caused desync bugs:
//  - day → custom: task vanished on reload (custom columns never saved)
//  - custom → day: task duplicated on reload (custom columns kept stale copy)
//  - custom → custom: move reverted on reload
export function useDragHandler(deps: {
	handleDragChange: () => boolean
	debouncedSave: () => void
	debouncedSaveCustomColumns: () => void
}) {
	function onDragChange() {
		deps.handleDragChange()
		deps.debouncedSave()
		deps.debouncedSaveCustomColumns()
	}
	return { onDragChange }
}
