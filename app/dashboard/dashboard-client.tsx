'use client'

import { useEffect, useState } from 'react'
import { useRouter } from 'next/navigation'
import { createClient } from '@/lib/supabase/client'
import type { User } from '@supabase/supabase-js'

interface PromptLog {
  id: string
  prompt: string
  response: string
  tokens_used: number
  created_at: string
}

interface DashboardClientProps {
  user: User
}

export default function DashboardClient({ user }: DashboardClientProps) {
  const router = useRouter()
  const supabase = createClient()
  
  const [accessToken, setAccessToken] = useState<string | null>(null)
  const [credits, setCredits] = useState<number | string | null>(null)
  const [prompt, setPrompt] = useState('')
  const [response, setResponse] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [logs, setLogs] = useState<PromptLog[]>([])
  const [logsLoading, setLogsLoading] = useState(true)
  const [isAdmin, setIsAdmin] = useState(false)
  const [models, setModels] = useState<string[]>([])
  const [selectedModel, setSelectedModel] = useState('gpt-4o-mini')

  // Get session and fetch initial data
  useEffect(() => {
    const init = async () => {
      const { data: { session } } = await supabase.auth.getSession()
      if (session?.access_token) {
        setAccessToken(session.access_token)
        fetchCredits(session.access_token)
        fetchLogs(session.access_token)
        fetchModels(session.access_token)
      }
    }
    init()
  }, [])

  const fetchCredits = async (token: string) => {
    try {
      const res = await fetch('/api/credits', {
        headers: { 'Authorization': `Bearer ${token}` }
      })
      const data = await res.json()
      if (res.ok) {
        setCredits(data.credits)
      }
    } catch (err) {
      console.error('Failed to fetch credits:', err)
    }
  }

  const fetchModels = async (token: string) => {
    try {
      const res = await fetch('/api/models', {
        headers: { 'Authorization': `Bearer ${token}` }
      })
      const data = await res.json()
      if (res.ok) {
        setModels(data.models || [])
        setIsAdmin(data.is_admin || false)
        if (data.default) {
          setSelectedModel(data.default)
        }
      }
    } catch (err) {
      console.error('Failed to fetch models:', err)
    }
  }

  const fetchLogs = async (token: string) => {
    setLogsLoading(true)
    try {
      const res = await fetch('/api/history', {
        headers: { 'Authorization': `Bearer ${token}` }
      })
      const data = await res.json()
      if (res.ok) {
        setLogs((data.history || []).slice(0, 10))
      }
    } catch (err) {
      console.error('Failed to fetch logs:', err)
    } finally {
      setLogsLoading(false)
    }
  }

  const handleSubmit = async () => {
    if (!prompt.trim() || loading || !accessToken) return
    
    setLoading(true)
    setError('')
    setResponse('')

    try {
      const body: Record<string, string> = { prompt: prompt.trim() }
      if (isAdmin && selectedModel) {
        body.model = selectedModel
      }

      const res = await fetch('/api/generate', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${accessToken}`
        },
        body: JSON.stringify(body)
      })

      const data = await res.json()

      if (!res.ok) {
        setError(data.error || 'Request failed')
        return
      }

      setResponse(data.response)
      if (data.credits_remaining !== 'unlimited') {
        setCredits(data.credits_remaining)
      }
      setPrompt('')
      
      fetchLogs(accessToken)
    } catch (err) {
      setError('Network error. Please try again.')
    } finally {
      setLoading(false)
    }
  }

  const handleLogout = async () => {
    await supabase.auth.signOut()
    router.push('/')
    router.refresh()
  }

  return (
    <div style={{ maxWidth: '800px', margin: '0 auto', padding: '20px', fontFamily: 'system-ui, sans-serif' }}>
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '30px', paddingBottom: '20px', borderBottom: '1px solid #eee' }}>
        <div>
          <h1 style={{ margin: 0, fontSize: '24px' }}>Dashboard</h1>
          {isAdmin && (
            <span style={{ fontSize: '12px', background: '#7c3aed', color: 'white', padding: '2px 8px', borderRadius: '4px', marginTop: '5px', display: 'inline-block' }}>
              Admin
            </span>
          )}
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '20px' }}>
          <span style={{ color: '#666', fontSize: '14px' }}>{user.email}</span>
          <button
            onClick={handleLogout}
            style={{ padding: '8px 16px', background: 'none', border: '1px solid #ddd', borderRadius: '4px', cursor: 'pointer' }}
          >
            Logout
          </button>
        </div>
      </div>

      {/* Credits Display */}
      <div style={{ background: '#f5f5f5', padding: '20px', borderRadius: '8px', marginBottom: '30px' }}>
        <div style={{ fontSize: '14px', color: '#666', marginBottom: '5px' }}>Credits Remaining</div>
        <div style={{ fontSize: '32px', fontWeight: 'bold' }}>
          {isAdmin ? '∞ Unlimited' : (credits !== null ? Number(credits).toLocaleString() : '...')}
        </div>
      </div>

      {/* Model Selection (Admin only) */}
      {isAdmin && models.length > 1 && (
        <div style={{ marginBottom: '20px' }}>
          <label style={{ display: 'block', marginBottom: '8px', fontWeight: '500' }}>
            Select Model
          </label>
          <select
            value={selectedModel}
            onChange={(e) => setSelectedModel(e.target.value)}
            style={{
              width: '100%',
              padding: '12px',
              fontSize: '14px',
              border: '1px solid #ddd',
              borderRadius: '8px',
              background: 'white',
              cursor: 'pointer'
            }}
          >
            {models.map((model) => (
              <option key={model} value={model}>
                {model}
              </option>
            ))}
          </select>
        </div>
      )}

      {/* Prompt Input */}
      <div style={{ marginBottom: '30px' }}>
        <label style={{ display: 'block', marginBottom: '8px', fontWeight: '500' }}>
          Enter your prompt
        </label>
        <textarea
          value={prompt}
          onChange={(e) => setPrompt(e.target.value)}
          placeholder="Type your prompt here..."
          disabled={loading}
          style={{
            width: '100%',
            minHeight: '120px',
            padding: '12px',
            fontSize: '14px',
            border: '1px solid #ddd',
            borderRadius: '8px',
            resize: 'vertical',
            boxSizing: 'border-box',
            fontFamily: 'inherit'
          }}
        />
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: '10px' }}>
          <span style={{ fontSize: '12px', color: '#999' }}>
            {prompt.length}/4000 characters
          </span>
          <button
            onClick={handleSubmit}
            disabled={loading || !prompt.trim() || prompt.length > 4000}
            style={{
              padding: '12px 24px',
              background: loading || !prompt.trim() || prompt.length > 4000 ? '#ccc' : '#000',
              color: '#fff',
              border: 'none',
              borderRadius: '6px',
              fontSize: '14px',
              fontWeight: '500',
              cursor: loading || !prompt.trim() || prompt.length > 4000 ? 'not-allowed' : 'pointer'
            }}
          >
            {loading ? 'Generating...' : 'Generate'}
          </button>
        </div>
      </div>

      {/* Error Display */}
      {error && (
        <div style={{
          background: '#fee',
          border: '1px solid #fcc',
          color: '#c00',
          padding: '12px 16px',
          borderRadius: '6px',
          marginBottom: '20px',
          fontSize: '14px'
        }}>
          {error}
        </div>
      )}

      {/* Response Display */}
      {response && (
        <div style={{ marginBottom: '30px' }}>
          <h3 style={{ fontSize: '16px', marginBottom: '10px' }}>Response</h3>
          <div style={{
            background: '#f9f9f9',
            border: '1px solid #eee',
            padding: '16px',
            borderRadius: '8px',
            whiteSpace: 'pre-wrap',
            fontSize: '14px',
            lineHeight: '1.6'
          }}>
            {response}
          </div>
        </div>
      )}

      {/* Prompt Logs */}
      <div style={{ borderTop: '1px solid #eee', paddingTop: '30px' }}>
        <h3 style={{ fontSize: '16px', marginBottom: '15px' }}>Recent Prompts</h3>
        
        {logsLoading ? (
          <div style={{ color: '#999', fontSize: '14px' }}>Loading...</div>
        ) : logs.length === 0 ? (
          <div style={{ color: '#999', fontSize: '14px' }}>No prompts yet.</div>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '15px' }}>
            {logs.map((log) => (
              <div
                key={log.id}
                style={{
                  background: '#fafafa',
                  border: '1px solid #eee',
                  borderRadius: '8px',
                  padding: '15px'
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '10px', fontSize: '12px', color: '#999' }}>
                  <span>{new Date(log.created_at).toLocaleString()}</span>
                  <span>{log.tokens_used} tokens</span>
                </div>
                <div style={{ marginBottom: '10px' }}>
                  <div style={{ fontSize: '12px', color: '#666', marginBottom: '4px' }}>Prompt:</div>
                  <div style={{ fontSize: '14px', color: '#333' }}>
                    {log.prompt.length > 100 ? log.prompt.slice(0, 100) + '...' : log.prompt}
                  </div>
                </div>
                <div>
                  <div style={{ fontSize: '12px', color: '#666', marginBottom: '4px' }}>Response:</div>
                  <div style={{ fontSize: '14px', color: '#555' }}>
                    {log.response.length > 150 ? log.response.slice(0, 150) + '...' : log.response}
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}
