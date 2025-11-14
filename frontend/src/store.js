import { create } from 'zustand'

export const useEventStore = create((set, get) => ({
  events: [],
  incidents: [],
  processEvents: [],
  networkEvents: [],
  fileEvents: [],
  connected: false,
  paused: false,
  filterSuspicious: false,
  searchQuery: '',
  
  addEvent: (event) => set((state) => {
    const updated = [event, ...state.events].slice(0, 500)
    
    let process = [...state.processEvents]
    let network = [...state.networkEvents]
    let file = [...state.fileEvents]
    
    if (event.event?.type === 'process_sample') {
      process = [event, ...process].slice(0, 200)
    } else if (event.event?.type === 'net_conn') {
      network = [event, ...network].slice(0, 200)
    } else if (event.event?.type === 'file_event') {
      file = [event, ...file].slice(0, 200)
    }
    
    return { events: updated, processEvents: process, networkEvents: network, fileEvents: file }
  }),
  
  setConnected: (connected) => set({ connected }),
  setPaused: (paused) => set({ paused }),
  setFilterSuspicious: (filter) => set({ filterSuspicious: filter }),
  setSearchQuery: (query) => set({ searchQuery: query }),
  
  setIncidents: (incidents) => set({ incidents }),
  
  clearEvents: () => set({ events: [], processEvents: [], networkEvents: [], fileEvents: [] }),
}))
