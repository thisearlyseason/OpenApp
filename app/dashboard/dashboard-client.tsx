'use client'

import { useEffect, useState } from 'react'
import { useRouter } from 'next/navigation'
import Link from 'next/link'
import { createClient } from '@/lib/supabase/client'
import type { User } from '@supabase/supabase-js'

interface HistoryItem {
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
  const [credits, setCredits] = useState(0)
  const [prompt, setPrompt] = useState('')
  const [response, setResponse] = useState('')
  const [promptLoading, setPromptLoading] = useState(false)
  const [history, setHistory] = useState<HistoryItem[]>([])
  const [activeTab, setActiveTab] = useState<'prompt' | 'history'>('prompt')
  const [accessToken, setAccessToken] = useState<string | null>(null)

  useEffect(() => {
    const getSession = async () => {
      const { data: { session } } = await supabase.auth.getSession()
      if (session?.access_token) {
        setAccessToken(session.access_token)
        fetchCredits(session.access_token)
      }
    }
    getSession()
  }, [supabase.auth])

  const fetchCredits = async (token: string) => {
    try {
      const res = await fetch('/api/credits', {
        headers: { 'Authorization': `Bearer ${token}` }
      })
      const data = await res.json()
      if (res.ok) setCredits(data.credits)
    } catch (err) {
      console.error('Failed to fetch credits:', err)
    }
  }

  const fetchHistory = async () => {
    if (!accessToken) return
    try {
      const res = await fetch('/api/history', {
        headers: { 'Authorization': `Bearer ${accessToken}` }
      })
      const data = await res.json()
      if (res.ok) setHistory(data.history || [])
    } catch (err) {
      console.error('Failed to fetch history:', err)
    }
  }

  const handleSubmitPrompt = async () => {
    if (!prompt.trim() || promptLoading || !accessToken) return

    setPromptLoading(true)
    setResponse('')

    try {
      const res = await fetch('/api/prompt', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${accessToken}`
        },
        body: JSON.stringify({ prompt: prompt.trim() })
      })

      const data = await res.json()

      if (!res.ok) {
        setResponse(`Error: ${data.error}`)
        return
      }

      setResponse(data.response)
      setCredits(data.creditsRemaining)
      setPrompt('')
    } catch (err) {
      setResponse('Error: Network error. Please try again.')
    } finally {
      setPromptLoading(false)
    }
  }

  const handleLogout = async () => {
    await supabase.auth.signOut()
    router.push('/')
    router.refresh()
  }

  return (
    <main className="min-h-screen bg-gradient-to-br from-slate-900 via-purple-900 to-slate-900">
      {/* Header */}
      <header className="border-b border-white/10 bg-black/20 backdrop-blur">
        <div className="container mx-auto px-4 h-16 flex items-center justify-between">
          <Link href="/" className="text-xl font-bold text-white">
            AI Prompt Platform
          </Link>

          <div className="flex items-center gap-6">
            <div className="flex items-center gap-2 bg-purple-600/20 px-4 py-2 rounded-full">
              <svg className="w-4 h-4 text-purple-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8c-1.657 0-3 .895-3 2s1.343 2 3 2 3 .895 3 2-1.343 2-3 2m0-8c1.11 0 2.08.402 2.599 1M12 8V7m0 1v8m0 0v1m0-1c-1.11 0-2.08-.402-2.599-1M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
              </svg>
              <span className="font-semibold text-purple-300">{credits}</span>
              <span className="text-purple-400 text-sm">credits</span>
            </div>

            <span className="text-gray-400 text-sm">{user.email}</span>

            <button
              onClick={handleLogout}
              className="text-gray-400 hover:text-white transition-colors"
              title="Logout"
            >
              <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1" />
              </svg>
            </button>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <div className="container mx-auto px-4 py-8 max-w-4xl">
        {/* Tabs */}
        <div className="flex gap-2 mb-8">
          <button
            onClick={() => setActiveTab('prompt')}
            className={`px-6 py-2 rounded-lg font-medium transition-colors ${
              activeTab === 'prompt'
                ? 'bg-purple-600 text-white'
                : 'bg-white/10 text-gray-400 hover:bg-white/20'
            }`}
          >
            Submit Prompt
          </button>
          <button
            onClick={() => {
              setActiveTab('history')
              fetchHistory()
            }}
            className={`px-6 py-2 rounded-lg font-medium transition-colors ${
              activeTab === 'history'
                ? 'bg-purple-600 text-white'
                : 'bg-white/10 text-gray-400 hover:bg-white/20'
            }`}
          >
            History
          </button>
        </div>

        {/* Prompt Tab */}
        {activeTab === 'prompt' && (
          <div className="space-y-6">
            <div className="bg-white/10 backdrop-blur rounded-xl p-6">
              <h2 className="text-xl font-semibold text-white mb-4">New Prompt</h2>
              <p className="text-gray-400 text-sm mb-4">Each request costs 1 credit</p>

              <textarea
                value={prompt}
                onChange={(e) => setPrompt(e.target.value)}
                placeholder="Enter your prompt here..."
                rows={4}
                className="w-full px-4 py-3 bg-white/5 border border-white/10 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-purple-500 resize-none"
                disabled={promptLoading}
              />

              <button
                onClick={handleSubmitPrompt}
                disabled={promptLoading || !prompt.trim() || credits < 1}
                className="mt-4 w-full py-3 bg-purple-600 text-white font-semibold rounded-lg hover:bg-purple-700 transition-colors disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2"
              >
                {promptLoading ? (
                  <>
                    <div className="animate-spin w-4 h-4 border-2 border-white border-t-transparent rounded-full"></div>
                    Processing...
                  </>
                ) : (
                  'Submit Prompt (1 credit)'
                )}
              </button>

              {credits < 1 && (
                <p className="mt-4 text-amber-400 text-sm text-center">
                  You have no credits remaining.
                </p>
              )}
            </div>

            {response && (
              <div className="bg-white/10 backdrop-blur rounded-xl p-6">
                <h3 className="text-lg font-semibold text-white mb-4">Response</h3>
                <p className="text-gray-300 whitespace-pre-wrap leading-relaxed">{response}</p>
              </div>
            )}
          </div>
        )}

        {/* History Tab */}
        {activeTab === 'history' && (
          <div className="bg-white/10 backdrop-blur rounded-xl p-6">
            <h2 className="text-xl font-semibold text-white mb-4">Prompt History</h2>

            {history.length === 0 ? (
              <p className="text-gray-400 text-center py-8">No prompts yet. Submit your first prompt!</p>
            ) : (
              <div className="space-y-4 max-h-[600px] overflow-y-auto">
                {history.map((item) => (
                  <div key={item.id} className="border-b border-white/10 pb-4 last:border-0">
                    <div className="flex items-center gap-2 mb-2">
                      <span className="text-xs bg-purple-600/30 text-purple-300 px-2 py-1 rounded">Prompt</span>
                      <span className="text-xs text-gray-500">
                        {new Date(item.created_at).toLocaleString()}
                      </span>
                    </div>
                    <p className="text-gray-300 text-sm bg-white/5 p-3 rounded-lg mb-2">{item.prompt}</p>

                    <span className="text-xs bg-green-600/30 text-green-300 px-2 py-1 rounded">Response</span>
                    <p className="text-gray-400 text-sm bg-white/5 p-3 rounded-lg mt-2 whitespace-pre-wrap">
                      {item.response}
                    </p>

                    <div className="flex gap-4 mt-2 text-xs text-gray-500">
                      <span>Tokens: {item.tokens_used}</span>
                      <span>Credits: {item.credits_used}</span>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
      </div>
    </main>
  )
}
