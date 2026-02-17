import { updateSession } from '@/lib/supabase/middleware'
import { NextResponse, type NextRequest } from 'next/server'

export async function middleware(request: NextRequest) {
  try {
    return await updateSession(request)
  } catch (error) {
    // On any error, continue without blocking
    console.error('Root middleware error:', error)
    return NextResponse.next()
  }
}

export const config = {
  matcher: [
    /*
     * Match only specific routes that need protection
     */
    '/dashboard/:path*',
    '/login',
    '/signup',
  ],
}
