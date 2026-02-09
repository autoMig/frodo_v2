import { Routes, Route } from 'react-router-dom'
import ApplicationList from './components/ApplicationList'
import ApplicationDetails from './components/ApplicationDetails'
import './App.css'

function App() {
  return (
    <div className="app">
      <header className="app-header">
        <h1>Frodo</h1>
        <p className="app-subtitle">Firewall Operations & Definition Orchestration</p>
      </header>

      <Routes>
        <Route path="/" element={<ApplicationList />} />
        <Route path="/applications/:app/:env" element={<ApplicationDetails />} />
      </Routes>
    </div>
  )
}

export default App
