import { useState, useRef, useCallback } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  BookOpen,
  FileUp,
  Search,
  Trash2,
  Upload,
  X,
} from 'lucide-react'
import { kbApi, type KBDocument, type KBSearchResult } from '../lib/api'

export default function KnowledgeBase() {
  const queryClient = useQueryClient()
  const [uploadTitle, setUploadTitle] = useState('')
  const [uploadDocType, setUploadDocType] = useState('reference')
  const [uploadContent, setUploadContent] = useState('')
  const [searchQuery, setSearchQuery] = useState('')
  const [searchResults, setSearchResults] = useState<KBSearchResult[]>([])
  const [isSearching, setIsSearching] = useState(false)
  const [isDragging, setIsDragging] = useState(false)
  const fileInputRef = useRef<HTMLInputElement>(null)

  const { data: documents = [] } = useQuery({
    queryKey: ['kb-documents'],
    queryFn: kbApi.list,
  })

  const createMutation = useMutation({
    mutationFn: (doc: { title: string; doc_type: string; content: string }) =>
      kbApi.create(doc),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['kb-documents'] })
      setUploadTitle('')
      setUploadContent('')
    },
  })

  const deleteMutation = useMutation({
    mutationFn: kbApi.delete,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['kb-documents'] }),
  })

  const handleUpload = () => {
    if (!uploadTitle || !uploadContent) return
    createMutation.mutate({
      title: uploadTitle,
      doc_type: uploadDocType,
      content: uploadContent,
    })
  }

  const handleFileRead = useCallback((file: File) => {
    setUploadTitle(file.name.replace(/\.[^.]+$/, ''))
    const reader = new FileReader()
    reader.onload = (e) => {
      setUploadContent(e.target?.result as string)
    }
    reader.readAsText(file)
  }, [])

  const handleDrop = useCallback(
    (e: React.DragEvent) => {
      e.preventDefault()
      setIsDragging(false)
      const file = e.dataTransfer.files[0]
      if (file) handleFileRead(file)
    },
    [handleFileRead],
  )

  const handleSearch = async () => {
    if (!searchQuery) return
    setIsSearching(true)
    try {
      const results = await kbApi.search(searchQuery, 3)
      setSearchResults(results)
    } catch {
      setSearchResults([])
    }
    setIsSearching(false)
  }

  return (
    <div className="p-8 space-y-8">
      <div>
        <h1 className="text-3xl font-bold">Knowledge Base</h1>
        <p className="text-muted-foreground mt-1">
          Upload CVEs, playbooks, and reference documents for agent context
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Upload Section */}
        <div className="bg-card border border-border rounded-lg p-6">
          <h2 className="text-lg font-semibold mb-4 flex items-center gap-2">
            <Upload className="h-5 w-5" />
            Upload Document
          </h2>

          {/* Drag & Drop Zone */}
          <div
            className={`border-2 border-dashed rounded-lg p-8 text-center transition-colors mb-4 ${
              isDragging ? 'border-primary bg-primary/5' : 'border-border'
            }`}
            onDragOver={(e) => { e.preventDefault(); setIsDragging(true) }}
            onDragLeave={() => setIsDragging(false)}
            onDrop={handleDrop}
            onClick={() => fileInputRef.current?.click()}
          >
            <FileUp className="h-10 w-10 mx-auto mb-3 text-muted-foreground" />
            <p className="text-sm text-muted-foreground">
              Drag and drop a file here, or click to browse
            </p>
            <input
              ref={fileInputRef}
              type="file"
              className="hidden"
              accept=".txt,.md,.json,.yaml,.yml,.csv"
              onChange={(e) => {
                const file = e.target.files?.[0]
                if (file) handleFileRead(file)
              }}
            />
          </div>

          <input
            type="text"
            placeholder="Document title"
            value={uploadTitle}
            onChange={(e) => setUploadTitle(e.target.value)}
            className="w-full bg-background border border-border rounded-md px-3 py-2 text-sm mb-3"
          />

          <select
            value={uploadDocType}
            onChange={(e) => setUploadDocType(e.target.value)}
            className="w-full bg-background border border-border rounded-md px-3 py-2 text-sm mb-3"
          >
            <option value="reference">Reference</option>
            <option value="cve">CVE</option>
            <option value="playbook">Playbook</option>
            <option value="technique">Technique</option>
          </select>

          <textarea
            placeholder="Document content (or drop a file above)"
            value={uploadContent}
            onChange={(e) => setUploadContent(e.target.value)}
            rows={6}
            className="w-full bg-background border border-border rounded-md px-3 py-2 text-sm mb-3 resize-none"
          />

          <button
            onClick={handleUpload}
            disabled={!uploadTitle || !uploadContent || createMutation.isPending}
            className="w-full px-4 py-2 bg-primary text-primary-foreground rounded-md hover:bg-primary/90 disabled:opacity-50 transition-colors"
          >
            {createMutation.isPending ? 'Uploading...' : 'Upload Document'}
          </button>
        </div>

        {/* Search Section */}
        <div className="bg-card border border-border rounded-lg p-6">
          <h2 className="text-lg font-semibold mb-4 flex items-center gap-2">
            <Search className="h-5 w-5" />
            Search Knowledge Base
          </h2>

          <div className="flex gap-2 mb-4">
            <input
              type="text"
              placeholder="Type a query..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && handleSearch()}
              className="flex-1 bg-background border border-border rounded-md px-3 py-2 text-sm"
            />
            <button
              onClick={handleSearch}
              disabled={isSearching}
              className="px-4 py-2 bg-primary text-primary-foreground rounded-md hover:bg-primary/90 disabled:opacity-50"
            >
              {isSearching ? '...' : 'Search'}
            </button>
          </div>

          {searchResults.length > 0 && (
            <div className="space-y-3">
              {searchResults.map((r, idx) => (
                <div key={idx} className="bg-background border border-border rounded-lg p-4">
                  <div className="flex items-center justify-between mb-2">
                    <span className="font-medium text-sm">{r.title}</span>
                    <span className="text-xs text-muted-foreground">
                      Score: {r.score.toFixed(2)}
                    </span>
                  </div>
                  <p className="text-xs text-muted-foreground line-clamp-3">{r.chunk}</p>
                </div>
              ))}
            </div>
          )}

          {searchQuery && searchResults.length === 0 && !isSearching && (
            <p className="text-center text-muted-foreground text-sm">No matching chunks found.</p>
          )}
        </div>
      </div>

      {/* Document List */}
      <div className="bg-card border border-border rounded-lg">
        <div className="p-6 border-b border-border">
          <h2 className="text-lg font-semibold flex items-center gap-2">
            <BookOpen className="h-5 w-5" />
            Documents ({documents.length})
          </h2>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b border-border text-left">
                <th className="px-6 py-3 text-xs font-medium text-muted-foreground uppercase">Title</th>
                <th className="px-6 py-3 text-xs font-medium text-muted-foreground uppercase">Type</th>
                <th className="px-6 py-3 text-xs font-medium text-muted-foreground uppercase">Scope</th>
                <th className="px-6 py-3 text-xs font-medium text-muted-foreground uppercase">Ingested</th>
                <th className="px-6 py-3 text-xs font-medium text-muted-foreground uppercase">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {documents.length === 0 ? (
                <tr>
                  <td colSpan={5} className="px-6 py-12 text-center text-muted-foreground">
                    No documents yet. Upload your first document above.
                  </td>
                </tr>
              ) : (
                documents.map((doc: KBDocument) => (
                  <tr key={doc.id} className="hover:bg-muted/30 transition-colors">
                    <td className="px-6 py-3 font-medium text-sm">{doc.title}</td>
                    <td className="px-6 py-3">
                      <span className="px-2 py-0.5 rounded-full text-xs font-medium bg-muted text-muted-foreground">
                        {doc.doc_type}
                      </span>
                    </td>
                    <td className="px-6 py-3 text-sm text-muted-foreground">Global</td>
                    <td className="px-6 py-3 text-sm text-muted-foreground">
                      {new Date(doc.created_at).toLocaleString()}
                    </td>
                    <td className="px-6 py-3">
                      <button
                        onClick={() => deleteMutation.mutate(doc.id)}
                        className="text-red-400 hover:text-red-300 transition-colors"
                      >
                        <Trash2 className="h-4 w-4" />
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}
