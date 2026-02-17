'use client'

import { useState, useEffect, useRef } from 'react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { ScrollArea } from '@/components/ui/scroll-area'
import { Separator } from '@/components/ui/separator'
import { Badge } from '@/components/ui/badge'
import { Textarea } from '@/components/ui/textarea'
import { Send, History, CreditCard, LogOut, Sparkles, User, Clock, Coins, Loader2 } from 'lucide-react'

export default function Home() {
  const [user, setUser] = useState(null)
  const [session, setSession] = useState(null)
  const [loading, setLoading] = useState(true)
  const [authLoading, setAuthLoading] = useState(false)
  const [promptLoading, setPromptLoading] = useState(false)
  
  // Auth form state
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [authError, setAuthError] = useState('')
  const [authTab, setAuthTab] = useState('login')
  
  // App state
  const [credits, setCredits] = useState(0)
  const [prompt, setPrompt] = useState('')
  const [response, setResponse] = useState('')
  const [history, setHistory] = useState([])
  const [activeTab, setActiveTab] = useState('prompt')
  
  const textareaRef = useRef(null)

  // Check for existing session on mount
  useEffect(() => {
    const storedSession = localStorage.getItem('session')
    const storedUser = localStorage.getItem('user')
    
    if (storedSession && storedUser) {
      try {
        setSession(JSON.parse(storedSession))
        setUser(JSON.parse(storedUser))
      } catch (e) {
        localStorage.removeItem('session')
        localStorage.removeItem('user')
      }
    }
    setLoading(false)
  }, [])

  // Fetch credits when user is logged in
  useEffect(() => {
    if (session?.access_token) {
      fetchCredits()
    }
  }, [session])

  const fetchCredits = async () => {
    try {
      const res = await fetch('/api/credits', {
        headers: {
          'Authorization': `Bearer ${session.access_token}`
        }
      })
      const data = await res.json()
      if (res.ok) {
        setCredits(data.credits)
      }
    } catch (error) {
      console.error('Failed to fetch credits:', error)
    }
  }

  const fetchHistory = async () => {
    try {
      const res = await fetch('/api/history', {
        headers: {
          'Authorization': `Bearer ${session.access_token}`
        }
      })
      const data = await res.json()
      if (res.ok) {
        setHistory(data.history || [])
      }
    } catch (error) {
      console.error('Failed to fetch history:', error)
    }
  }

  const handleAuth = async (isSignup) => {
    setAuthError('')
    setAuthLoading(true)
    
    try {
      const endpoint = isSignup ? '/api/auth/signup' : '/api/auth/login'
      const res = await fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password })
      })
      
      const data = await res.json()
      
      if (!res.ok) {
        setAuthError(data.error || 'Authentication failed')
        return
      }
      
      if (data.session) {
        localStorage.setItem('session', JSON.stringify(data.session))
        localStorage.setItem('user', JSON.stringify(data.user))
        setSession(data.session)
        setUser(data.user)
        setEmail('')
        setPassword('')
      } else if (isSignup) {
        setAuthError('Please check your email to confirm your account, then login.')
        setAuthTab('login')
      }
    } catch (error) {
      setAuthError('Network error. Please try again.')
    } finally {
      setAuthLoading(false)
    }
  }

  const handleLogout = () => {
    localStorage.removeItem('session')
    localStorage.removeItem('user')
    setSession(null)
    setUser(null)
    setCredits(0)
    setHistory([])
    setResponse('')
    setPrompt('')
  }

  const handleSubmitPrompt = async () => {
    if (!prompt.trim() || promptLoading) return
    
    setPromptLoading(true)
    setResponse('')
    
    try {
      const res = await fetch('/api/prompt', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${session.access_token}`
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
      
      // Refresh history if on history tab
      if (activeTab === 'history') {
        fetchHistory()
      }
    } catch (error) {
      setResponse('Error: Network error. Please try again.')
    } finally {
      setPromptLoading(false)
    }
  }

  const handleKeyDown = (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault()
      handleSubmitPrompt()
    }
  }

  // Loading state
  if (loading) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-violet-50 via-purple-50 to-fuchsia-50 flex items-center justify-center">
        <Loader2 className="h-8 w-8 animate-spin text-violet-600" />
      </div>
    )
  }

  // Auth screen
  if (!session) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-violet-50 via-purple-50 to-fuchsia-50 flex items-center justify-center p-4">
        <Card className="w-full max-w-md shadow-xl border-0 bg-white/80 backdrop-blur">
          <CardHeader className="text-center space-y-2">
            <div className="mx-auto w-16 h-16 bg-gradient-to-br from-violet-500 to-fuchsia-500 rounded-2xl flex items-center justify-center mb-2">
              <Sparkles className="h-8 w-8 text-white" />
            </div>
            <CardTitle className="text-2xl font-bold bg-gradient-to-r from-violet-600 to-fuchsia-600 bg-clip-text text-transparent">
              AI Prompt Platform
            </CardTitle>
            <CardDescription>Submit prompts and get AI-powered responses</CardDescription>
          </CardHeader>
          <CardContent>
            <Tabs value={authTab} onValueChange={setAuthTab}>
              <TabsList className="grid w-full grid-cols-2 mb-6">
                <TabsTrigger value="login">Login</TabsTrigger>
                <TabsTrigger value="signup">Sign Up</TabsTrigger>
              </TabsList>
              
              <div className="space-y-4">
                <div className="space-y-2">
                  <Input
                    type="email"
                    placeholder="Email"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    className="h-11"
                  />
                </div>
                <div className="space-y-2">
                  <Input
                    type="password"
                    placeholder="Password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    className="h-11"
                    onKeyDown={(e) => e.key === 'Enter' && handleAuth(authTab === 'signup')}
                  />
                </div>
                
                {authError && (
                  <div className="p-3 bg-red-50 border border-red-200 rounded-lg text-red-600 text-sm">
                    {authError}
                  </div>
                )}
                
                <Button
                  className="w-full h-11 bg-gradient-to-r from-violet-500 to-fuchsia-500 hover:from-violet-600 hover:to-fuchsia-600"
                  onClick={() => handleAuth(authTab === 'signup')}
                  disabled={authLoading}
                >
                  {authLoading ? (
                    <Loader2 className="h-4 w-4 animate-spin mr-2" />
                  ) : null}
                  {authTab === 'login' ? 'Login' : 'Create Account'}
                </Button>
                
                {authTab === 'signup' && (
                  <p className="text-xs text-center text-muted-foreground">
                    New users receive {process.env.NEXT_PUBLIC_INITIAL_CREDITS || 100} free credits
                  </p>
                )}
              </div>
            </Tabs>
          </CardContent>
        </Card>
      </div>
    )
  }

  // Main app
  return (
    <div className="min-h-screen bg-gradient-to-br from-violet-50 via-purple-50 to-fuchsia-50">
      {/* Header */}
      <header className="border-b bg-white/80 backdrop-blur sticky top-0 z-50">
        <div className="container mx-auto px-4 h-16 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 bg-gradient-to-br from-violet-500 to-fuchsia-500 rounded-xl flex items-center justify-center">
              <Sparkles className="h-5 w-5 text-white" />
            </div>
            <h1 className="text-xl font-bold bg-gradient-to-r from-violet-600 to-fuchsia-600 bg-clip-text text-transparent">
              AI Prompt Platform
            </h1>
          </div>
          
          <div className="flex items-center gap-4">
            <div className="flex items-center gap-2 bg-violet-100 px-4 py-2 rounded-full">
              <Coins className="h-4 w-4 text-violet-600" />
              <span className="font-semibold text-violet-700">{credits}</span>
              <span className="text-violet-600 text-sm">credits</span>
            </div>
            
            <div className="flex items-center gap-2 text-sm text-muted-foreground">
              <User className="h-4 w-4" />
              <span>{user?.email}</span>
            </div>
            
            <Button variant="ghost" size="icon" onClick={handleLogout}>
              <LogOut className="h-4 w-4" />
            </Button>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="container mx-auto px-4 py-8 max-w-4xl">
        <Tabs value={activeTab} onValueChange={(v) => {
          setActiveTab(v)
          if (v === 'history') fetchHistory()
        }}>
          <TabsList className="grid w-full grid-cols-2 mb-8">
            <TabsTrigger value="prompt" className="flex items-center gap-2">
              <Send className="h-4 w-4" />
              Submit Prompt
            </TabsTrigger>
            <TabsTrigger value="history" className="flex items-center gap-2">
              <History className="h-4 w-4" />
              History
            </TabsTrigger>
          </TabsList>

          {/* Prompt Tab */}
          <TabsContent value="prompt" className="space-y-6">
            <Card className="shadow-lg border-0 bg-white/80 backdrop-blur">
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Sparkles className="h-5 w-5 text-violet-500" />
                  New Prompt
                </CardTitle>
                <CardDescription>
                  Enter your prompt below. Each request costs 1 credit.
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="space-y-2">
                  <Textarea
                    ref={textareaRef}
                    placeholder="Enter your prompt here..."
                    value={prompt}
                    onChange={(e) => setPrompt(e.target.value)}
                    onKeyDown={handleKeyDown}
                    rows={4}
                    className="resize-none"
                    disabled={promptLoading}
                  />
                  <p className="text-xs text-muted-foreground">
                    Press Enter to submit, Shift+Enter for new line
                  </p>
                </div>
                
                <Button
                  className="w-full bg-gradient-to-r from-violet-500 to-fuchsia-500 hover:from-violet-600 hover:to-fuchsia-600"
                  onClick={handleSubmitPrompt}
                  disabled={promptLoading || !prompt.trim() || credits < 1}
                >
                  {promptLoading ? (
                    <>
                      <Loader2 className="h-4 w-4 animate-spin mr-2" />
                      Processing...
                    </>
                  ) : (
                    <>
                      <Send className="h-4 w-4 mr-2" />
                      Submit Prompt (1 credit)
                    </>
                  )}
                </Button>
                
                {credits < 1 && (
                  <div className="p-3 bg-amber-50 border border-amber-200 rounded-lg text-amber-700 text-sm text-center">
                    You have no credits remaining.
                  </div>
                )}
              </CardContent>
            </Card>

            {/* Response Card */}
            {response && (
              <Card className="shadow-lg border-0 bg-white/80 backdrop-blur">
                <CardHeader>
                  <CardTitle className="text-lg">Response</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="prose prose-sm max-w-none">
                    <p className="whitespace-pre-wrap text-gray-700 leading-relaxed">{response}</p>
                  </div>
                </CardContent>
              </Card>
            )}
          </TabsContent>

          {/* History Tab */}
          <TabsContent value="history">
            <Card className="shadow-lg border-0 bg-white/80 backdrop-blur">
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <History className="h-5 w-5 text-violet-500" />
                  Prompt History
                </CardTitle>
                <CardDescription>
                  Your recent prompts and responses
                </CardDescription>
              </CardHeader>
              <CardContent>
                {history.length === 0 ? (
                  <div className="text-center py-12 text-muted-foreground">
                    <History className="h-12 w-12 mx-auto mb-4 opacity-50" />
                    <p>No prompts yet. Submit your first prompt!</p>
                  </div>
                ) : (
                  <ScrollArea className="h-[500px] pr-4">
                    <div className="space-y-4">
                      {history.map((item, index) => (
                        <div key={item.id || index}>
                          <div className="space-y-3 py-4">
                            <div className="flex items-start justify-between gap-4">
                              <div className="flex-1">
                                <div className="flex items-center gap-2 mb-2">
                                  <Badge variant="outline" className="bg-violet-50 text-violet-700 border-violet-200">
                                    Prompt
                                  </Badge>
                                  <span className="text-xs text-muted-foreground flex items-center gap-1">
                                    <Clock className="h-3 w-3" />
                                    {new Date(item.created_at).toLocaleString()}
                                  </span>
                                </div>
                                <p className="text-sm text-gray-700 bg-gray-50 p-3 rounded-lg">
                                  {item.prompt}
                                </p>
                              </div>
                            </div>
                            
                            <div>
                              <Badge variant="outline" className="bg-fuchsia-50 text-fuchsia-700 border-fuchsia-200 mb-2">
                                Response
                              </Badge>
                              <p className="text-sm text-gray-600 bg-gray-50 p-3 rounded-lg whitespace-pre-wrap">
                                {item.response}
                              </p>
                            </div>
                            
                            <div className="flex gap-4 text-xs text-muted-foreground">
                              <span>Tokens: {item.tokens_used || 0}</span>
                              <span>Credits used: {item.credits_used || 1}</span>
                            </div>
                          </div>
                          {index < history.length - 1 && <Separator />}
                        </div>
                      ))}
                    </div>
                  </ScrollArea>
                )}
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>
      </main>
    </div>
  )
}
